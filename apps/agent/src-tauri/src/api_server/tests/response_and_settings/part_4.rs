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
