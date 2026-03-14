#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use clawdstrike_broker_protocol::{
    binding_proof_message, sha256_hex, sign_capability, BindingProof, BrokerCapability,
    BrokerDestination, BrokerExecuteRequest, BrokerExecutionEvidence, BrokerExecutionOutcome,
    BrokerExecutionPhase, BrokerMintedIdentityKind, BrokerProvider, BrokerRequest,
    BrokerRequestConstraints, CredentialRef, HttpMethod, ProofBinding, ProofBindingMode, UrlScheme,
    BROKER_EXECUTION_ID_HEADER,
};
use clawdstrike_brokerd::{
    api::create_router,
    config::{Config, SecretBackendConfig},
    state::AppState,
};
use hush_core::{sha256, Keypair};
use tempfile::tempdir;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Default)]
struct EvidenceState {
    evidence: std::sync::Arc<Mutex<Vec<BrokerExecutionEvidence>>>,
}

fn active_status_payload(capability_id: String) -> serde_json::Value {
    serde_json::json!({
        "capability": {
            "capability_id": capability_id,
            "provider": "openai",
            "state": "active",
            "issued_at": Utc::now(),
            "expires_at": Utc::now() + chrono::Duration::seconds(60),
            "policy_hash": "hash-test",
            "secret_ref_id": "test/secret",
            "url": "https://example.test/v1/action",
            "method": "POST",
            "execution_count": 0
        }
    })
}

fn assert_started_then_completed(
    evidence: &[BrokerExecutionEvidence],
    capability_id: &str,
    secret_ref_id: &str,
) {
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].phase, BrokerExecutionPhase::Started);
    assert_eq!(evidence[0].capability_id, capability_id);
    assert_eq!(evidence[0].secret_ref_id, secret_ref_id);
    assert_eq!(evidence[1].phase, BrokerExecutionPhase::Completed);
    assert_eq!(evidence[1].capability_id, capability_id);
    assert_eq!(evidence[1].secret_ref_id, secret_ref_id);
}

#[tokio::test]
async fn brokerd_executes_openai_request_and_persists_evidence() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/v1/responses",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer sk-test-openai")
            );
            assert!(body.contains("\"model\":\"gpt-4.1-mini\""));
            Json(serde_json::json!({
                "id": "resp_test",
                "object": "response",
                "output_text": "brokered"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "openai/dev": "sk-test-openai"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let binding_secret = "loopback-binding-secret";
    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"hello\"}";
    let capability = BrokerCapability {
        capability_id: "cap-123".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-123".to_string(),
        session_id: Some("sess-1".to_string()),
        endpoint_agent_id: Some("agent-1".to_string()),
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: Some(ProofBinding {
            mode: ProofBindingMode::Loopback,
            binding_sha256: Some(sha256(binding_secret.as_bytes()).to_hex()),
            key_thumbprint: None,
            workload_id: None,
        }),
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: Some(binding_secret.to_string()),
            binding_proof: None,
            request: BrokerRequest {
                url: format!("http://127.0.0.1:{}/v1/responses", upstream_addr.port()),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["capability_id"], "cap-123");
    assert_eq!(payload["status"], 200);
    assert_eq!(payload["provider"], "openai");

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-123", "openai/dev");
    assert_eq!(evidence[1].status_code, Some(200));
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("request_model")
            .map(String::as_str),
        Some("gpt-4.1-mini")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_id")
            .map(String::as_str),
        Some("resp_test")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_records_minted_identity_from_github_app_secret_descriptor() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/repos/acme/widget/issues",
        post(|headers: axum::http::HeaderMap| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer ghs_wave5_token")
            );
            Json(serde_json::json!({
                "id": 44,
                "html_url": "https://github.example/acme/widget/issues/44"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "github/dev": serde_json::json!({
                "type": "github_app_installation",
                "installation_token": "ghs_wave5_token",
                "installation_id": "42",
                "app_id": "9001",
                "expires_in_secs": 300
            }).to_string()
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"title":"Wave 5 issue","body":"minted identity"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-wave5-github".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-wave5-github".to_string(),
        session_id: None,
        endpoint_agent_id: Some("agent:endpoint".to_string()),
        runtime_agent_id: Some("agent:runner".to_string()),
        runtime_agent_kind: Some("delegate".to_string()),
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "github/dev".to_string(),
            provider: BrokerProvider::Github,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/repos/acme/widget/issues".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: sign_capability(&capability, &signer).unwrap(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/repos/acme/widget/issues",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-wave5-github", "github/dev");
    let minted_identity = evidence[1]
        .minted_identity
        .clone()
        .expect("minted identity");
    assert_eq!(
        minted_identity.kind,
        BrokerMintedIdentityKind::GithubAppInstallation
    );
    assert_eq!(minted_identity.subject, "github-installation:42");

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_freezes_when_tripwire_secret_is_touched() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "openai/dev": serde_json::json!({
                "type": "tripwire",
                "reason": "honeypot credential touched"
            }).to_string()
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"model":"gpt-4.1-mini"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-tripwire".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-tripwire".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(8443),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: sign_capability(&capability, &signer).unwrap(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: "http://127.0.0.1:8443/v1/responses".to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_TRIPWIRE_TRIGGERED");

    let capabilities_payload: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{}/v1/capabilities", broker_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(capabilities_payload["frozen"], true);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].suspicion_reason.as_deref(),
        Some("honeypot credential touched")
    );
    assert_eq!(
        evidence[0].outcome,
        Some(BrokerExecutionOutcome::Incomplete)
    );

    broker_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_github_issue_create_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/repos/acme/widget/issues",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer ghs_test_123")
            );
            assert_eq!(
                headers
                    .get(axum::http::header::ACCEPT)
                    .and_then(|value| value.to_str().ok()),
                Some("application/vnd.github+json")
            );
            assert_eq!(
                headers
                    .get("x-github-api-version")
                    .and_then(|value| value.to_str().ok()),
                Some("2022-11-28")
            );
            assert!(headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("clawdstrike-brokerd")));
            assert!(body.contains("\"title\":\"Brokered issue\""));
            Json(serde_json::json!({
                "id": 42,
                "number": 17,
                "html_url": "https://github.example/acme/widget/issues/17"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("github upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "github/dev": "ghs_test_123"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"title":"Brokered issue","body":"opened via broker"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-github".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-github".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "github/dev".to_string(),
            provider: BrokerProvider::Github,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/repos/acme/widget/issues".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/repos/acme/widget/issues",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "github");
    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-github", "github/dev");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("issues.create")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("repo_owner")
            .map(String::as_str),
        Some("acme")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("repo_name")
            .map(String::as_str),
        Some("widget")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_slack_post_message_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/api/chat.postMessage",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer xoxb-test-123")
            );
            assert!(body.contains("\"channel\":\"C123456\""));
            Json(serde_json::json!({
                "ok": true,
                "channel": "C123456",
                "ts": "1710000000.000100"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("slack upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "slack/dev": "xoxb-test-123"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"channel":"C123456","text":"hello from broker"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-slack".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-slack".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "slack/dev".to_string(),
            provider: BrokerProvider::Slack,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/api/chat.postMessage".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/api/chat.postMessage",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "slack");
    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-slack", "slack/dev");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("chat.postMessage")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("channel")
            .map(String::as_str),
        Some("C123456")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_rejects_expired_capability() {
    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({ "openai/dev": "sk-test-openai" })).unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: "http://127.0.0.1:9".to_string(),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("broker server");
    });

    let capability = BrokerCapability {
        capability_id: "cap-expired".to_string(),
        issued_at: Utc::now() - chrono::Duration::seconds(120),
        expires_at: Utc::now() - chrono::Duration::seconds(60),
        policy_hash: "hash-expired".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(8080),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints::default(),
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: "http://127.0.0.1:8080/v1/responses".to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::new(),
                body: None,
                body_sha256: None,
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_CAPABILITY_EXPIRED");

    task.abort();
}

#[tokio::test]
async fn brokerd_rejects_revoked_capability_from_hushd_status() {
    let hushd_router = Router::new().route(
        "/api/v1/broker/capabilities/{capability_id}/status",
        get(|Path(capability_id): Path<String>| async move {
            Json(serde_json::json!({
                "capability": {
                    "capability_id": capability_id,
                    "provider": "openai",
                    "state": "revoked",
                    "issued_at": Utc::now(),
                    "expires_at": Utc::now() + chrono::Duration::seconds(60),
                    "policy_hash": "hash-test",
                    "secret_ref_id": "openai/dev",
                    "url": "http://127.0.0.1:8080/v1/responses",
                    "method": "POST",
                    "execution_count": 0
                }
            }))
        }),
    );
    let hushd_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hushd_addr = hushd_listener.local_addr().unwrap();
    let hushd_task = tokio::spawn(async move {
        axum::serve(hushd_listener, hushd_router)
            .await
            .expect("mock hushd");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({ "openai/dev": "sk-test-openai" })).unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", hushd_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("broker server");
    });

    let capability = BrokerCapability {
        capability_id: "cap-revoked".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-live".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(8080),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints::default(),
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: "http://127.0.0.1:8080/v1/responses".to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::new(),
                body: None,
                body_sha256: None,
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_CAPABILITY_REVOKED");

    task.abort();
    hushd_task.abort();
}

#[tokio::test]
async fn brokerd_accepts_dpop_binding_with_env_secret_backend() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/v1/responses",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer sk-test-openai-env")
            );
            assert!(body.contains("\"input\":\"hello from dpop\""));
            Json(serde_json::json!({
                "id": "resp_dpop",
                "object": "response",
                "output_text": "brokered-dpop"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let env_prefix = format!("CLAWDSTRIKE_TEST_SECRET_{}_", Uuid::new_v4().simple());
    let env_key = format!("{env_prefix}OPENAI_PROD");
    unsafe {
        std::env::set_var(&env_key, "sk-test-openai-env");
    }

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::Env {
            prefix: env_prefix.clone(),
        },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"hello from dpop\"}";
    let request_body_sha256 = sha256(request_body.as_bytes()).to_hex();
    let request_url = format!("http://127.0.0.1:{}/v1/responses", upstream_addr.port());
    let binding_key = Keypair::generate();
    let binding_public_key = binding_key.public_key().to_hex();
    let binding_issued_at = Utc::now();
    let binding_nonce = "nonce-dpop-1";
    let binding_signature = binding_key
        .sign(
            binding_proof_message(
                "cap-dpop",
                &HttpMethod::POST,
                &request_url,
                Some(&request_body_sha256),
                &binding_issued_at,
                binding_nonce,
            )
            .as_bytes(),
        )
        .to_hex();

    let capability = BrokerCapability {
        capability_id: "cap-dpop".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-dpop".to_string(),
        session_id: Some("sess-dpop".to_string()),
        endpoint_agent_id: Some("agent-dpop".to_string()),
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/prod".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: Some("prod".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some(sha256_hex(&binding_public_key)),
            workload_id: None,
        }),
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: Some(BindingProof {
                mode: ProofBindingMode::Dpop,
                public_key: Some(binding_public_key.clone()),
                signature: Some(binding_signature),
                issued_at: Some(binding_issued_at),
                nonce: Some(binding_nonce.to_string()),
            }),
            request: BrokerRequest {
                url: request_url,
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(request_body_sha256),
            },
        })
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["capability_id"], "cap-dpop");
    assert_eq!(payload["status"], 200);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-dpop", "openai/prod");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_id")
            .map(String::as_str),
        Some("resp_dpop")
    );

    unsafe {
        std::env::remove_var(&env_key);
    }
    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_rejects_openai_stream_requests() {
    let authority_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |Json(_evidence): Json<BrokerExecutionEvidence>| async move {
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        );
    let authority_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority_addr = authority_listener.local_addr().unwrap();
    let authority_task = tokio::spawn(async move {
        axum::serve(authority_listener, authority_router)
            .await
            .expect("authority server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({ "openai/dev": "sk-test-openai" })).unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", authority_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("broker server");
    });

    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"hello\",\"stream\":true}";
    let capability = BrokerCapability {
        capability_id: "cap-stream".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-stream".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(8080),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: "http://127.0.0.1:8080/v1/responses".to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_STREAM_UNSUPPORTED");

    task.abort();
    authority_task.abort();
}

#[tokio::test]
async fn brokerd_resolves_secret_from_managed_http_backend() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let secret_router = Router::new().route(
        "/v1/secrets/{*secret_ref}",
        get(
            |Path(secret_ref): Path<String>, headers: axum::http::HeaderMap| async move {
                assert_eq!(secret_ref, "openai/managed");
                assert_eq!(
                    headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok()),
                    Some("Bearer managed-token")
                );
                Json(serde_json::json!({ "value": "sk-managed-openai" }))
            },
        ),
    );
    let secret_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secret_addr = secret_listener.local_addr().unwrap();
    let secret_task = tokio::spawn(async move {
        axum::serve(secret_listener, secret_router)
            .await
            .expect("secret server");
    });

    let upstream_router = Router::new().route(
        "/v1/responses",
        post(|headers: axum::http::HeaderMap| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer sk-managed-openai")
            );
            Json(serde_json::json!({
                "id": "resp_managed",
                "object": "response",
                "output_text": "managed-secret"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::Http {
            base_url: format!("http://{}", secret_addr),
            bearer_token: Some("managed-token".to_string()),
            path_prefix: "/v1/secrets".to_string(),
        },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"managed\"}";
    let capability = BrokerCapability {
        capability_id: "cap-managed".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-managed".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/managed".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!("http://127.0.0.1:{}/v1/responses", upstream_addr.port()),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["status"], 200);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-managed", "openai/managed");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_id")
            .map(String::as_str),
        Some("resp_managed")
    );

    broker_task.abort();
    upstream_task.abort();
    secret_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_generic_https_requests_with_header_secret() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/v1/widgets",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok()),
                Some("secret-123")
            );
            assert_eq!(body, "{\"op\":\"sync\"}");
            Json(serde_json::json!({ "ok": true }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "generic/dev": "{\"type\":\"header\",\"header_name\":\"x-api-key\",\"value\":\"secret-123\"}"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: true,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"op\":\"sync\"}";
    let capability = BrokerCapability {
        capability_id: "cap-generic".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-generic".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "generic/dev".to_string(),
            provider: BrokerProvider::GenericHttps,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/widgets".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!("http://127.0.0.1:{}/v1/widgets", upstream_addr.port()),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "generic_https");
    assert_eq!(payload["status"], 200);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-generic", "generic/dev");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("auth_mode")
            .map(String::as_str),
        Some("header")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_github_issue_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/repos/acme/widget/issues",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer ghs_test_token")
            );
            assert_eq!(
                headers
                    .get(axum::http::header::ACCEPT)
                    .and_then(|value| value.to_str().ok()),
                Some("application/vnd.github+json")
            );
            assert_eq!(
                headers
                    .get("x-github-api-version")
                    .and_then(|value| value.to_str().ok()),
                Some("2022-11-28")
            );
            assert!(body.contains("\"title\":\"Brokered issue\""));
            Json(serde_json::json!({ "id": 42, "number": 42 }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "github/dev": "ghs_test_token"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"title\":\"Brokered issue\",\"body\":\"Created by brokerd\"}";
    let capability = BrokerCapability {
        capability_id: "cap-github".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-github".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "github/dev".to_string(),
            provider: BrokerProvider::Github,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/repos/acme/widget/issues".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(4096),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/repos/acme/widget/issues",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "github");
    assert_eq!(payload["status"], 200);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-github", "github/dev");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("issues.create")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("repo_owner")
            .map(String::as_str),
        Some("acme")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("repo_name")
            .map(String::as_str),
        Some("widget")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_slack_message_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/api/chat.postMessage",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer xoxb-slack-token")
            );
            assert!(body.contains("\"channel\":\"C123\""));
            Json(serde_json::json!({ "ok": true, "ts": "171234.000001" }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "slack/dev": "xoxb-slack-token"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"channel\":\"C123\",\"text\":\"hello from brokerd\"}";
    let capability = BrokerCapability {
        capability_id: "cap-slack".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-slack".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "slack/dev".to_string(),
            provider: BrokerProvider::Slack,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/api/chat.postMessage".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(4096),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/api/chat.postMessage",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "slack");
    assert_eq!(payload["status"], 200);

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-slack", "slack/dev");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("chat.postMessage")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("channel")
            .map(String::as_str),
        Some("C123")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_streams_openai_responses_and_records_start_completion_evidence() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/v1/responses",
        post(|headers: axum::http::HeaderMap| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer sk-stream-openai")
            );
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                Body::from_stream(tokio_stream::iter(vec![
                    Ok::<_, std::io::Error>(Bytes::from("data: {\"delta\":\"hel\"}\n\n")),
                    Ok::<_, std::io::Error>(Bytes::from("data: {\"delta\":\"lo\"}\n\n")),
                    Ok::<_, std::io::Error>(Bytes::from("data: [DONE]\n\n")),
                ])),
            )
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "openai/stream": "sk-stream-openai"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"hello\",\"stream\":true}";
    let capability = BrokerCapability {
        capability_id: "cap-stream-ok".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-stream-ok".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/stream".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(4096),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(true),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute/stream", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!("http://127.0.0.1:{}/v1/responses", upstream_addr.port()),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let execution_id = response
        .headers()
        .get(BROKER_EXECUTION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap();
    let streamed_body = response.text().await.unwrap();
    assert!(streamed_body.contains("data: [DONE]"));

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let evidence = evidence_state.evidence.lock().await.clone();
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].phase, BrokerExecutionPhase::Started);
    assert_eq!(evidence[0].execution_id, execution_id);
    assert_eq!(evidence[0].outcome, None);
    assert_eq!(evidence[1].phase, BrokerExecutionPhase::Completed);
    assert_eq!(evidence[1].execution_id, evidence[0].execution_id);
    assert_eq!(evidence[1].outcome, Some(BrokerExecutionOutcome::Success));
    assert_eq!(evidence[1].stream_chunk_count, Some(3));
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_mode")
            .map(String::as_str),
        Some("stream")
    );
    assert!(evidence[1].response_body_sha256.is_some());

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_github_issue_comment_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(serde_json::json!({
                    "capability": {
                        "capability_id": capability_id,
                        "provider": "github",
                        "state": "active",
                        "issued_at": Utc::now(),
                        "expires_at": Utc::now() + chrono::Duration::seconds(60),
                        "policy_hash": "hash-github",
                        "secret_ref_id": "github/prod",
                        "url": "http://127.0.0.1/v1/placeholder",
                        "method": "POST",
                        "execution_count": 0
                    }
                }))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/repos/backbay-labs/clawdstrike/issues/42/comments",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer ghp_test_github")
            );
            assert_eq!(
                headers
                    .get("x-github-api-version")
                    .and_then(|value| value.to_str().ok()),
                Some("2022-11-28")
            );
            assert!(body.contains("\"body\":\"LGTM\""));
            Json(serde_json::json!({
                "id": 9001,
                "html_url": "https://github.com/backbay-labs/clawdstrike/issues/42#issuecomment-9001",
                "node_id": "IC_kwDOTest"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("github upstream");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "github/prod": "ghp_test_github"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"body":"LGTM"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-github-comment".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-github".to_string(),
        session_id: Some("sess-github".to_string()),
        endpoint_agent_id: Some("agent-github".to_string()),
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "github/prod".to_string(),
            provider: BrokerProvider::Github,
            tenant_id: None,
            environment: Some("prod".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/repos/backbay-labs/clawdstrike/issues/42/comments".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/repos/backbay-labs/clawdstrike/issues/42/comments",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "github");

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-github-comment", "github/prod");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("issues.comment.create")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_html_url")
            .map(String::as_str),
        Some("https://github.com/backbay-labs/clawdstrike/issues/42#issuecomment-9001")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_executes_slack_chat_post_message_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(serde_json::json!({
                    "capability": {
                        "capability_id": capability_id,
                        "provider": "slack",
                        "state": "active",
                        "issued_at": Utc::now(),
                        "expires_at": Utc::now() + chrono::Duration::seconds(60),
                        "policy_hash": "hash-slack",
                        "secret_ref_id": "slack/prod",
                        "url": "http://127.0.0.1/api/chat.postMessage",
                        "method": "POST",
                        "execution_count": 0
                    }
                }))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/api/chat.postMessage",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer xoxb-test-slack")
            );
            assert!(body.contains("\"channel\":\"C123\""));
            Json(serde_json::json!({
                "ok": true,
                "channel": "C123",
                "ts": "1710000000.000100"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("slack upstream");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "slack/prod": "xoxb-test-slack"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = r#"{"channel":"C123","text":"hello from broker"}"#;
    let capability = BrokerCapability {
        capability_id: "cap-slack-post".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-slack".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "slack/prod".to_string(),
            provider: BrokerProvider::Slack,
            tenant_id: None,
            environment: Some("prod".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/api/chat.postMessage".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/api/chat.postMessage",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(sha256(request_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["provider"], "slack");

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_started_then_completed(&evidence, "cap-slack-post", "slack/prod");
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("operation")
            .map(String::as_str),
        Some("chat.postMessage")
    );
    assert_eq!(
        evidence[1]
            .provider_metadata
            .get("response_ts")
            .map(String::as_str),
        Some("1710000000.000100")
    );

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_local_freeze_blocks_execution_and_tracks_capability() {
    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "openai/dev": "sk-frozen"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: "http://127.0.0.1:9".to_string(),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("broker server");
    });

    let freeze_response = reqwest::Client::new()
        .post(format!("http://{}/v1/admin/freeze", addr))
        .json(&serde_json::json!({ "frozen": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(freeze_response.status(), StatusCode::OK);

    let capability = BrokerCapability {
        capability_id: "cap-local-freeze".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-freeze".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: None,
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(8080),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints::default(),
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: "http://127.0.0.1:8080/v1/responses".to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::new(),
                body: None,
                body_sha256: None,
            },
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_FROZEN");

    let capabilities = reqwest::Client::new()
        .get(format!("http://{}/v1/capabilities", addr))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(capabilities["frozen"], true);
    assert_eq!(
        capabilities["capabilities"][0]["capability_id"],
        "cap-local-freeze"
    );

    task.abort();
}

#[tokio::test]
async fn brokerd_executes_typed_github_and_slack_requests() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new()
        .route(
            "/repos/backbay-labs/clawdstrike/issues",
            post(|headers: axum::http::HeaderMap, body: String| async move {
                assert_eq!(
                    headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok()),
                    Some("Bearer ghs_test_secret")
                );
                let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(payload["title"], "Wave 4 bug");
                Json(serde_json::json!({
                    "id": 9001,
                    "number": 42,
                    "html_url": "https://github.com/backbay-labs/clawdstrike/issues/42"
                }))
            }),
        )
        .route(
            "/api/chat.postMessage",
            post(|headers: axum::http::HeaderMap, body: String| async move {
                assert_eq!(
                    headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok()),
                    Some("Bearer xoxb-test-secret")
                );
                let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(payload["channel"], "C123");
                assert_eq!(payload["text"], "wave 4 shipped");
                Json(serde_json::json!({
                    "ok": true,
                    "channel": "C123",
                    "ts": "1710286400.000100"
                }))
            }),
        );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "github/dev": "ghs_test_secret",
            "slack/dev": "xoxb-test-secret"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let github_body = serde_json::json!({
        "title": "Wave 4 bug",
        "body": "typed github execution"
    })
    .to_string();
    let github_capability = BrokerCapability {
        capability_id: "cap-github".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-github".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "github/dev".to_string(),
            provider: BrokerProvider::Github,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/repos/backbay-labs/clawdstrike/issues".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let github_response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: sign_capability(&github_capability, &signer).unwrap(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/repos/backbay-labs/clawdstrike/issues",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(github_body.clone()),
                body_sha256: Some(sha256(github_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();
    let github_status = github_response.status();
    let github_body = github_response.text().await.unwrap();
    assert_eq!(github_status, StatusCode::OK, "{github_body}");
    let github_payload: serde_json::Value = serde_json::from_str(&github_body).unwrap();
    assert_eq!(github_payload["provider"], "github");

    let slack_body = serde_json::json!({
        "channel": "C123",
        "text": "wave 4 shipped"
    })
    .to_string();
    let slack_capability = BrokerCapability {
        capability_id: "cap-slack".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-slack".to_string(),
        session_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: None,
        secret_ref: CredentialRef {
            id: "slack/dev".to_string(),
            provider: BrokerProvider::Slack,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/api/chat.postMessage".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let slack_response = reqwest::Client::new()
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: sign_capability(&slack_capability, &signer).unwrap(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: format!(
                    "http://127.0.0.1:{}/api/chat.postMessage",
                    upstream_addr.port()
                ),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(slack_body.clone()),
                body_sha256: Some(sha256(slack_body.as_bytes()).to_hex()),
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(slack_response.status(), StatusCode::OK);
    let slack_payload: serde_json::Value = slack_response.json().await.unwrap();
    assert_eq!(slack_payload["provider"], "slack");

    let evidence = evidence_state.evidence.lock().await.clone();
    assert_eq!(evidence.len(), 4);
    assert!(evidence.iter().any(|item| {
        item.phase == BrokerExecutionPhase::Completed
            && item.provider_metadata.get("operation").map(String::as_str) == Some("issues.create")
    }));
    assert!(evidence.iter().any(|item| {
        item.phase == BrokerExecutionPhase::Completed
            && item.provider_metadata.get("operation").map(String::as_str)
                == Some("chat.postMessage")
    }));

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}

#[tokio::test]
async fn brokerd_operator_apis_expose_wallet_and_enforce_revoke_freeze() {
    let evidence_state = EvidenceState::default();
    let evidence_router = Router::new()
        .route(
            "/api/v1/broker/evidence",
            post(
                |State(state): State<EvidenceState>,
                 Json(evidence): Json<BrokerExecutionEvidence>| async move {
                    state.evidence.lock().await.push(evidence);
                    Json(serde_json::json!({ "accepted": true }))
                },
            ),
        )
        .route(
            "/api/v1/broker/capabilities/{capability_id}/status",
            get(|Path(capability_id): Path<String>| async move {
                Json(active_status_payload(capability_id))
            }),
        )
        .with_state(evidence_state.clone());
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_addr = evidence_listener.local_addr().unwrap();
    let evidence_task = tokio::spawn(async move {
        axum::serve(evidence_listener, evidence_router)
            .await
            .expect("evidence server");
    });

    let upstream_router = Router::new().route(
        "/v1/responses",
        post(|headers: axum::http::HeaderMap, body: String| async move {
            assert_eq!(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer sk-operator")
            );
            assert!(body.contains("\"model\":\"gpt-4.1-mini\""));
            Json(serde_json::json!({
                "id": "resp_operator",
                "object": "response",
                "output_text": "ok"
            }))
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_router)
            .await
            .expect("upstream server");
    });

    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("secrets.json");
    std::fs::write(
        &secret_file,
        serde_json::to_string(&serde_json::json!({
            "openai/dev": "sk-operator"
        }))
        .unwrap(),
    )
    .unwrap();

    let signer = Keypair::generate();
    let state = AppState::from_config(Config {
        listen: "127.0.0.1:0".to_string(),
        hushd_base_url: format!("http://{}", evidence_addr),
        hushd_token: None,
        secret_backend: SecretBackendConfig::File { path: secret_file },
        trusted_hushd_public_keys: vec![signer.public_key()],
        request_timeout_secs: 5,
        binding_proof_ttl_secs: 60,
        allow_http_loopback: true,
        allow_private_upstream_hosts: false,
        allow_invalid_upstream_tls: false,
        admin_token: None,
    })
    .unwrap();
    let router = create_router(state);
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_addr = broker_listener.local_addr().unwrap();
    let broker_task = tokio::spawn(async move {
        axum::serve(broker_listener, router)
            .await
            .expect("broker server");
    });

    let request_body = "{\"model\":\"gpt-4.1-mini\",\"input\":\"operator\"}";
    let request_body_sha256 = sha256(request_body.as_bytes()).to_hex();
    let request_url = format!("http://127.0.0.1:{}/v1/responses", upstream_addr.port());
    let capability = BrokerCapability {
        capability_id: "cap-operator".to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        policy_hash: "hash-operator".to_string(),
        session_id: Some("sess-operator".to_string()),
        endpoint_agent_id: Some("endpoint-1".to_string()),
        runtime_agent_id: None,
        runtime_agent_kind: None,
        origin_fingerprint: Some("origin-1".to_string()),
        secret_ref: CredentialRef {
            id: "openai/dev".to_string(),
            provider: BrokerProvider::Openai,
            tenant_id: None,
            environment: Some("dev".to_string()),
            labels: BTreeMap::new(),
        },
        proof_binding: None,
        destination: BrokerDestination {
            scheme: UrlScheme::Http,
            host: "127.0.0.1".to_string(),
            port: Some(upstream_addr.port()),
            method: HttpMethod::POST,
            exact_paths: vec!["/v1/responses".to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: vec!["content-type".to_string()],
            max_body_bytes: Some(2048),
            require_request_body_sha256: Some(true),
            allow_redirects: Some(false),
            stream_response: Some(false),
            max_executions: None,
        },
        evidence_required: true,
        intent_preview: None,
        lineage: None,
    };
    let signed_capability = sign_capability(&capability, &signer).unwrap();
    let client = reqwest::Client::new();

    let execute_response = client
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability.clone(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: request_url.clone(),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(request_body_sha256.clone()),
            },
        })
        .send()
        .await
        .unwrap();
    let execute_status = execute_response.status();
    let execute_body = execute_response.text().await.unwrap();
    assert_eq!(execute_status, StatusCode::OK, "{execute_body}");

    let capabilities_payload: serde_json::Value = client
        .get(format!("http://{}/v1/capabilities", broker_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(capabilities_payload["frozen"], false);
    assert_eq!(
        capabilities_payload["capabilities"][0]["capability_id"],
        "cap-operator"
    );
    assert_eq!(
        capabilities_payload["capabilities"][0]["provider"],
        "openai"
    );

    let executions_payload: serde_json::Value = client
        .get(format!("http://{}/v1/executions", broker_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        executions_payload["executions"][0]["capability_id"],
        "cap-operator"
    );
    assert_eq!(executions_payload["executions"][0]["phase"], "completed");
    assert_eq!(executions_payload["timeline"].as_array().unwrap().len(), 2);

    let revoke_payload: serde_json::Value = client
        .post(format!(
            "http://{}/v1/capabilities/{}/revoke",
            broker_addr, "cap-operator"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revoke_payload["revoked"], true);

    let revoked_response = client
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: signed_capability,
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: request_url.clone(),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(request_body_sha256.clone()),
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_response.status(), StatusCode::FORBIDDEN);
    let revoked_payload: serde_json::Value = revoked_response.json().await.unwrap();
    assert_eq!(
        revoked_payload["error"]["code"],
        "BROKER_CAPABILITY_REVOKED"
    );

    let freeze_response = client
        .post(format!("http://{}/v1/admin/freeze", broker_addr))
        .json(&serde_json::json!({ "frozen": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(freeze_response.status(), StatusCode::OK);

    let frozen_capability = BrokerCapability {
        capability_id: "cap-frozen".to_string(),
        ..capability
    };
    let frozen_response = client
        .post(format!("http://{}/v1/execute", broker_addr))
        .json(&BrokerExecuteRequest {
            capability: sign_capability(&frozen_capability, &signer).unwrap(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: request_url,
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(request_body.to_string()),
                body_sha256: Some(request_body_sha256),
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(frozen_response.status(), StatusCode::FORBIDDEN);
    let frozen_payload: serde_json::Value = frozen_response.json().await.unwrap();
    assert_eq!(frozen_payload["error"]["code"], "BROKER_FROZEN");

    broker_task.abort();
    upstream_task.abort();
    evidence_task.abort();
}
