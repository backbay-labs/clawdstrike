#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use clawdstrike_broker_protocol::{
    verify_completion_bundle, BrokerExecutionEvidence, BrokerExecutionOutcome,
    BrokerExecutionPhase, BrokerMintedIdentity, BrokerMintedIdentityKind,
};
use hush_core::{Keypair, PublicKey};
use hush_multi_agent::{AgentCapability, AgentId, DelegationClaims, SignedDelegationToken};
use hushd::config::{BrokerApiConfig, Config, RateLimitConfig};

use common::TestDaemon;

fn write_policy_with_contents(contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hushd-broker-policy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.yaml");
    std::fs::write(&path, contents).unwrap();
    path
}

fn write_policy() -> PathBuf {
    write_policy_with_contents(
        r#"
version: "1.5.0"
name: "broker-test"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "127.0.0.1"
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "127.0.0.1"
      port: 8443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
      allowed_headers: ["content-type"]
      require_body_sha256: true
"#,
    )
}

fn broker_daemon() -> TestDaemon {
    let policy_path = write_policy();
    TestDaemon::spawn_with_config(Config {
        policy_path: Some(policy_path),
        broker: BrokerApiConfig {
            enabled: true,
            capability_ttl_secs: 120,
            allow_http_loopback: true,
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    })
}

fn broker_daemon_with_policy(policy: &str) -> TestDaemon {
    let policy_path = write_policy_with_contents(policy);
    TestDaemon::spawn_with_config(Config {
        policy_path: Some(policy_path),
        broker: BrokerApiConfig {
            enabled: true,
            capability_ttl_secs: 120,
            allow_http_loopback: true,
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    })
}

async fn issue_test_capability(client: &reqwest::Client, daemon: &TestDaemon) -> serde_json::Value {
    let response = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    response.json().await.unwrap()
}

#[tokio::test]
async fn issues_broker_capability_for_authorized_request() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let payload = issue_test_capability(&client, &daemon).await;
    assert!(payload["capability"].is_string());
    assert_eq!(
        payload["policy_hash"].as_str().map(|s| s.is_empty()),
        Some(false)
    );
}

#[tokio::test]
async fn rejects_broker_capability_for_unauthorized_path() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/chat/completions",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_PROVIDER_DENIED");
}

#[tokio::test]
async fn capability_status_revoke_and_provider_freeze_round_trip() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let issue = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(issue.status().is_success());
    let issued: serde_json::Value = issue.json().await.unwrap();
    let capability_id = issued["capability_id"].as_str().unwrap();

    let status = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{}/status",
            daemon.url, capability_id
        ))
        .send()
        .await
        .unwrap();
    assert!(status.status().is_success());
    let payload: serde_json::Value = status.json().await.unwrap();
    assert_eq!(payload["capability"]["state"], "active");

    let revoke = client
        .post(format!(
            "{}/api/v1/broker/capabilities/{}/revoke",
            daemon.url, capability_id
        ))
        .json(&serde_json::json!({
            "reason": "operator freeze drill"
        }))
        .send()
        .await
        .unwrap();
    assert!(revoke.status().is_success());
    let revoked: serde_json::Value = revoke.json().await.unwrap();
    assert_eq!(revoked["capability"]["state"], "revoked");
    assert_eq!(
        revoked["capability"]["state_reason"],
        "operator freeze drill"
    );

    let freeze = client
        .post(format!(
            "{}/api/v1/broker/providers/openai/freeze",
            daemon.url
        ))
        .json(&serde_json::json!({
            "reason": "maintenance"
        }))
        .send()
        .await
        .unwrap();
    assert!(freeze.status().is_success());
    let frozen: serde_json::Value = freeze.json().await.unwrap();
    assert_eq!(frozen["frozen_providers"][0]["provider"], "openai");

    let replay = client
        .post(format!(
            "{}/api/v1/broker/capabilities/{}/replay",
            daemon.url, capability_id
        ))
        .send()
        .await
        .unwrap();
    assert!(replay.status().is_success());
    let replay_payload: serde_json::Value = replay.json().await.unwrap();
    assert_eq!(replay_payload["capability_id"], capability_id);
    assert_eq!(replay_payload["current_state"], "revoked");
    assert_eq!(replay_payload["provider_frozen"], true);
    assert_eq!(replay_payload["would_allow"], false);
}

#[tokio::test]
async fn rejects_dpop_capability_without_key_thumbprint() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "dpop"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_PROOF_BINDING_INVALID");
}

#[tokio::test]
async fn ingests_broker_evidence_and_persists_audit_event() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let issued = issue_test_capability(&client, &daemon).await;
    let capability_id = issued["capability_id"].as_str().unwrap().to_string();

    let response = client
        .post(format!("{}/api/v1/broker/evidence", daemon.url))
        .json(&BrokerExecutionEvidence {
            execution_id: "exec-123".to_string(),
            capability_id,
            provider: clawdstrike_broker_protocol::BrokerProvider::Openai,
            phase: BrokerExecutionPhase::Completed,
            executed_at: Utc::now(),
            secret_ref_id: "openai/dev".to_string(),
            url: "http://127.0.0.1:8443/v1/responses".to_string(),
            method: clawdstrike_broker_protocol::HttpMethod::POST,
            request_body_sha256: Some("abc123".to_string()),
            response_body_sha256: Some("def456".to_string()),
            status_code: Some(200),
            bytes_sent: 128,
            bytes_received: 256,
            stream_chunk_count: None,
            provider_metadata: BTreeMap::from([(
                "operation".to_string(),
                "responses.create".to_string(),
            )]),
            outcome: Some(BrokerExecutionOutcome::Success),
            minted_identity: None,
            preview_id: None,
            lineage: None,
            suspicion_reason: None,
        })
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let ack: serde_json::Value = response.json().await.unwrap();
    assert_eq!(ack["accepted"], true);

    let audit = client
        .get(format!("{}/api/v1/audit?action_type=broker", daemon.url))
        .send()
        .await
        .unwrap();
    assert!(audit.status().is_success());
    let payload: serde_json::Value = audit.json().await.unwrap();
    let events = payload["events"].as_array().unwrap();
    assert!(events
        .iter()
        .any(|event| event["event_type"] == "broker_evidence_recorded"));
}

#[tokio::test]
async fn exposes_broker_public_key() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/v1/broker/public-key", daemon.url))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let payload: serde_json::Value = response.json().await.unwrap();
    let public_key = payload["public_key"].as_str().unwrap();
    assert!(!public_key.is_empty());
}

#[tokio::test]
async fn lists_status_and_replays_capabilities() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let issued = issue_test_capability(&client, &daemon).await;
    let capability_id = issued["capability_id"].as_str().unwrap();

    let list_response = client
        .get(format!("{}/api/v1/broker/capabilities", daemon.url))
        .send()
        .await
        .unwrap();
    assert!(list_response.status().is_success());
    let listed: serde_json::Value = list_response.json().await.unwrap();
    let capabilities = listed["capabilities"].as_array().unwrap();
    assert!(capabilities
        .iter()
        .any(|capability| capability["capability_id"] == capability_id));

    let status_response = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{capability_id}",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(status_response.status().is_success());
    let status_payload: serde_json::Value = status_response.json().await.unwrap();
    assert_eq!(status_payload["capability"]["state"], "active");

    let replay_response = client
        .post(format!(
            "{}/api/v1/broker/capabilities/{capability_id}/replay",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(replay_response.status().is_success());
    let replay_payload: serde_json::Value = replay_response.json().await.unwrap();
    assert_eq!(replay_payload["capability_id"], capability_id);
    assert_eq!(replay_payload["would_allow"], true);
}

#[tokio::test]
async fn wave5_preview_lineage_and_completion_bundle_round_trip() {
    let daemon = broker_daemon_with_policy(
        r#"
version: "1.5.0"
name: "broker-wave5"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "127.0.0.1"
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "127.0.0.1"
      port: 8443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
      allowed_headers: ["content-type"]
      require_body_sha256: true
      require_intent_preview: true
      approval_required_risk_levels: ["high"]
"#,
    );
    let client = reqwest::Client::new();

    let preview_response = client
        .post(format!("{}/api/v1/broker/previews", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body": r#"{"model":"gpt-4.1-mini","tools":[{"type":"function","name":"tool"}]}"#,
            "body_sha256": "f26069c2426b1ffaf147423647d0e80ebd852866b7886f063dbeed8818e12e7f"
        }))
        .send()
        .await
        .unwrap();
    assert!(preview_response.status().is_success());
    let preview_payload: serde_json::Value = preview_response.json().await.unwrap();
    let preview = &preview_payload["preview"];
    let preview_id = preview["preview_id"].as_str().unwrap();
    assert_eq!(preview["approval_required"], true);
    assert_eq!(preview["approval_state"], "pending");

    let denied_issue = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_issue.status(), reqwest::StatusCode::FORBIDDEN);

    let approve_response = client
        .post(format!(
            "{}/api/v1/broker/previews/{preview_id}/approve",
            daemon.url
        ))
        .json(&serde_json::json!({ "approver": "test-user" }))
        .send()
        .await
        .unwrap();
    assert!(approve_response.status().is_success());

    let signer = Keypair::generate();
    let claims = DelegationClaims::new(
        AgentId::new("agent:planner").unwrap(),
        AgentId::new("agent:runner").unwrap(),
        Utc::now().timestamp(),
        (Utc::now() + chrono::Duration::seconds(60)).timestamp(),
        vec![AgentCapability::NetworkEgress {
            hosts: vec!["127.0.0.1".to_string()],
        }],
    )
    .unwrap();
    let delegation = SignedDelegationToken::sign_with_public_key(claims, &signer).unwrap();

    let issue_response = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "f26069c2426b1ffaf147423647d0e80ebd852866b7886f063dbeed8818e12e7f",
            "endpoint_agent_id": "agent:endpoint",
            "runtime_agent_id": "agent:runner",
            "runtime_agent_kind": "delegate",
            "preview_id": preview_id,
            "delegation_token": serde_json::to_string(&delegation).unwrap(),
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(issue_response.status().is_success());
    let issued: serde_json::Value = issue_response.json().await.unwrap();
    let capability_id = issued["capability_id"].as_str().unwrap();

    let evidence_response = client
        .post(format!("{}/api/v1/broker/evidence", daemon.url))
        .json(&BrokerExecutionEvidence {
            execution_id: "exec-wave5".to_string(),
            capability_id: capability_id.to_string(),
            provider: clawdstrike_broker_protocol::BrokerProvider::Openai,
            phase: BrokerExecutionPhase::Completed,
            executed_at: Utc::now(),
            secret_ref_id: "openai/dev".to_string(),
            url: "http://127.0.0.1:8443/v1/responses".to_string(),
            method: clawdstrike_broker_protocol::HttpMethod::POST,
            request_body_sha256: Some("abc123".to_string()),
            response_body_sha256: Some("def456".to_string()),
            status_code: Some(200),
            bytes_sent: 64,
            bytes_received: 128,
            stream_chunk_count: None,
            provider_metadata: BTreeMap::from([(
                "operation".to_string(),
                "responses.create".to_string(),
            )]),
            outcome: Some(BrokerExecutionOutcome::Success),
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::GithubAppInstallation,
                subject: "github-installation:42".to_string(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                metadata: BTreeMap::from([("installation_id".to_string(), "42".to_string())]),
            }),
            preview_id: Some(preview_id.to_string()),
            lineage: Some(clawdstrike_broker_protocol::BrokerDelegationLineage {
                token_jti: delegation.claims.jti.clone(),
                parent_token_jti: delegation.claims.chn.last().cloned(),
                chain: delegation.claims.chn.clone(),
                depth: delegation.claims.chn.len(),
                issuer: delegation.claims.iss.to_string(),
                subject: delegation.claims.sub.to_string(),
                purpose: delegation.claims.pur.clone(),
            }),
            suspicion_reason: None,
        })
        .send()
        .await
        .unwrap();
    assert!(evidence_response.status().is_success());

    let detail_response = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{capability_id}",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(detail_response.status().is_success());
    let detail_payload: serde_json::Value = detail_response.json().await.unwrap();
    assert_eq!(
        detail_payload["capability"]["intent_preview"]["preview_id"],
        preview_id
    );
    assert_eq!(
        detail_payload["capability"]["lineage"]["subject"],
        "agent:runner"
    );
    assert_eq!(
        detail_payload["capability"]["minted_identity"]["kind"],
        "github_app_installation"
    );

    let bundle_response = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{capability_id}/bundle",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(bundle_response.status().is_success());
    let bundle_payload: serde_json::Value = bundle_response.json().await.unwrap();
    let envelope = bundle_payload["envelope"].as_str().unwrap();

    let public_key_response = client
        .get(format!("{}/api/v1/broker/public-key", daemon.url))
        .send()
        .await
        .unwrap();
    let public_key_payload: serde_json::Value = public_key_response.json().await.unwrap();
    let public_key = PublicKey::from_hex(public_key_payload["public_key"].as_str().unwrap())
        .expect("public key");
    let verified_bundle = verify_completion_bundle(envelope, &[public_key]).expect("bundle");
    assert_eq!(verified_bundle.capability.capability_id, capability_id);
    assert_eq!(verified_bundle.executions.len(), 1);
}

#[tokio::test]
async fn preview_body_hash_is_bound_to_capability_requests() {
    let daemon = broker_daemon_with_policy(
        r#"
version: "1.5.0"
name: "broker-preview-hash-binding"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "127.0.0.1"
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "127.0.0.1"
      port: 8443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
      allowed_headers: ["content-type"]
      require_body_sha256: true
      require_intent_preview: true
      approval_required_risk_levels: ["high"]
"#,
    );
    let client = reqwest::Client::new();

    let preview_response = client
        .post(format!("{}/api/v1/broker/previews", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body": r#"{"model":"gpt-4.1-mini","tools":[{"type":"function","name":"tool"}]}"#,
            "body_sha256": "f26069c2426b1ffaf147423647d0e80ebd852866b7886f063dbeed8818e12e7f"
        }))
        .send()
        .await
        .unwrap();
    assert!(preview_response.status().is_success());
    let preview_payload: serde_json::Value = preview_response.json().await.unwrap();
    let preview = &preview_payload["preview"];
    assert_eq!(preview["approval_required"], true);
    assert_eq!(preview["approval_state"], "pending");
    assert_eq!(
        preview["body_sha256"],
        "f26069c2426b1ffaf147423647d0e80ebd852866b7886f063dbeed8818e12e7f"
    );
    let preview_id = preview["preview_id"].as_str().unwrap();

    let approve_response = client
        .post(format!(
            "{}/api/v1/broker/previews/{preview_id}/approve",
            daemon.url
        ))
        .json(&serde_json::json!({ "approver": "test-user" }))
        .send()
        .await
        .unwrap();
    assert!(approve_response.status().is_success());

    let mut issue_request = serde_json::json!({
        "provider": "openai",
        "url": "http://127.0.0.1:8443/v1/responses",
        "method": "POST",
        "secret_ref": "openai/dev",
        "body_sha256": "f26069c2426b1ffaf147423647d0e80ebd852866b7886f063dbeed8818e12e7f",
        "preview_id": preview_id,
        "proof_binding": {
            "mode": "loopback",
            "binding_sha256": "deadbeef"
        }
    });
    let first_issue = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&issue_request)
        .send()
        .await
        .unwrap();
    assert!(first_issue.status().is_success());

    issue_request["body_sha256"] = serde_json::json!("mismatch");
    let mismatch_issue = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&issue_request)
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch_issue.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = mismatch_issue.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "BROKER_PREVIEW_MISMATCH");
}

#[tokio::test]
async fn revokes_and_freezes_broker_capabilities() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let issued = issue_test_capability(&client, &daemon).await;
    let capability_id = issued["capability_id"].as_str().unwrap();

    let revoke_response = client
        .post(format!(
            "{}/api/v1/broker/capabilities/{capability_id}/revoke",
            daemon.url
        ))
        .json(&serde_json::json!({ "reason": "containment" }))
        .send()
        .await
        .unwrap();
    assert!(revoke_response.status().is_success());
    let revoked: serde_json::Value = revoke_response.json().await.unwrap();
    assert_eq!(revoked["capability"]["state"], "revoked");
    assert_eq!(revoked["capability"]["state_reason"], "containment");

    let freeze_response = client
        .post(format!(
            "{}/api/v1/broker/providers/openai/freeze",
            daemon.url
        ))
        .json(&serde_json::json!({ "reason": "provider outage" }))
        .send()
        .await
        .unwrap();
    assert!(freeze_response.status().is_success());
    let frozen: serde_json::Value = freeze_response.json().await.unwrap();
    assert_eq!(frozen["frozen_providers"][0]["provider"], "openai");

    let list_frozen_response = client
        .get(format!("{}/api/v1/broker/providers/freeze", daemon.url))
        .send()
        .await
        .unwrap();
    assert!(list_frozen_response.status().is_success());
    let frozen_list: serde_json::Value = list_frozen_response.json().await.unwrap();
    assert_eq!(frozen_list["frozen_providers"][0]["provider"], "openai");

    let unfreeze_response = client
        .delete(format!(
            "{}/api/v1/broker/providers/openai/freeze",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(unfreeze_response.status().is_success());
    let unfrozen: serde_json::Value = unfreeze_response.json().await.unwrap();
    assert_eq!(unfrozen["frozen_providers"], serde_json::json!([]));
}

#[tokio::test]
async fn capability_detail_tracks_executions_and_supports_panic_revoke() {
    let daemon = broker_daemon();
    let client = reqwest::Client::new();

    let issued = issue_test_capability(&client, &daemon).await;
    let capability_id = issued["capability_id"].as_str().unwrap();

    for evidence in [
        BrokerExecutionEvidence {
            execution_id: "exec-start".to_string(),
            capability_id: capability_id.to_string(),
            provider: clawdstrike_broker_protocol::BrokerProvider::Openai,
            phase: BrokerExecutionPhase::Started,
            executed_at: Utc::now() - chrono::Duration::seconds(5),
            secret_ref_id: "openai/dev".to_string(),
            url: "http://127.0.0.1:8443/v1/responses".to_string(),
            method: clawdstrike_broker_protocol::HttpMethod::POST,
            request_body_sha256: Some("abc123".to_string()),
            response_body_sha256: None,
            status_code: None,
            bytes_sent: 64,
            bytes_received: 0,
            stream_chunk_count: Some(0),
            provider_metadata: BTreeMap::new(),
            outcome: None,
            minted_identity: None,
            preview_id: None,
            lineage: None,
            suspicion_reason: None,
        },
        BrokerExecutionEvidence {
            execution_id: "exec-complete".to_string(),
            capability_id: capability_id.to_string(),
            provider: clawdstrike_broker_protocol::BrokerProvider::Openai,
            phase: BrokerExecutionPhase::Completed,
            executed_at: Utc::now(),
            secret_ref_id: "openai/dev".to_string(),
            url: "http://127.0.0.1:8443/v1/responses".to_string(),
            method: clawdstrike_broker_protocol::HttpMethod::POST,
            request_body_sha256: Some("abc123".to_string()),
            response_body_sha256: Some("def456".to_string()),
            status_code: Some(200),
            bytes_sent: 64,
            bytes_received: 128,
            stream_chunk_count: Some(3),
            provider_metadata: BTreeMap::from([(
                "operation".to_string(),
                "responses.create".to_string(),
            )]),
            outcome: Some(BrokerExecutionOutcome::Success),
            minted_identity: None,
            preview_id: None,
            lineage: None,
            suspicion_reason: None,
        },
    ] {
        let response = client
            .post(format!("{}/api/v1/broker/evidence", daemon.url))
            .json(&evidence)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    let detail_response = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{capability_id}",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(detail_response.status().is_success());
    let detail_payload: serde_json::Value = detail_response.json().await.unwrap();
    let executions = detail_payload["executions"].as_array().unwrap();
    assert_eq!(executions.len(), 2);
    assert_eq!(executions[0]["phase"], "completed");
    assert_eq!(executions[1]["phase"], "started");

    let revoke_all_response = client
        .post(format!(
            "{}/api/v1/broker/capabilities/revoke-all",
            daemon.url
        ))
        .json(&serde_json::json!({ "reason": "incident drill" }))
        .send()
        .await
        .unwrap();
    assert!(revoke_all_response.status().is_success());
    let revoke_all_payload: serde_json::Value = revoke_all_response.json().await.unwrap();
    assert_eq!(revoke_all_payload["revoked_count"], 1);

    let status_response = client
        .get(format!(
            "{}/api/v1/broker/capabilities/{capability_id}/status",
            daemon.url
        ))
        .send()
        .await
        .unwrap();
    assert!(status_response.status().is_success());
    let status_payload: serde_json::Value = status_response.json().await.unwrap();
    assert_eq!(status_payload["capability"]["state"], "revoked");
    assert_eq!(
        status_payload["capability"]["state_reason"],
        "incident drill"
    );

    let freeze_response = client
        .post(format!(
            "{}/api/v1/broker/providers/openai/freeze",
            daemon.url
        ))
        .json(&serde_json::json!({ "reason": "provider hold" }))
        .send()
        .await
        .unwrap();
    assert!(freeze_response.status().is_success());

    let denied_issue = client
        .post(format!("{}/api/v1/broker/capabilities", daemon.url))
        .json(&serde_json::json!({
            "provider": "openai",
            "url": "http://127.0.0.1:8443/v1/responses",
            "method": "POST",
            "secret_ref": "openai/dev",
            "body_sha256": "abc123",
            "proof_binding": {
                "mode": "loopback",
                "binding_sha256": "deadbeef"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_issue.status(), reqwest::StatusCode::FORBIDDEN);
    let denied_payload: serde_json::Value = denied_issue.json().await.unwrap();
    assert_eq!(denied_payload["error"]["code"], "BROKER_PROVIDER_FROZEN");
}
