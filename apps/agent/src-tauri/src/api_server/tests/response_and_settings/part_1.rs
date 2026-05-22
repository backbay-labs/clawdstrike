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

