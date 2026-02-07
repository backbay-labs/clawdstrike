//! Integration tests for clawdstriked HTTP API
//!
//! These tests require either:
//! 1. A running daemon at CLAWDSTRIKE_TEST_URL (for local development)
//! 2. The daemon binary at CLAWDSTRIKE_BIN (for CI, will spawn automatically)

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::daemon_url;
use hushd::config::{
    AuditConfig, AuditEncryptionConfig, AuditEncryptionKeySource, Config, RateLimitConfig,
};

/// Helper to get client and URL
fn test_setup() -> (reqwest::Client, String) {
    (reqwest::Client::new(), daemon_url())
}

#[tokio::test]
async fn test_health_endpoint() {
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/health", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let health: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert!(health["version"].is_string());
    assert!(health["uptime_secs"].is_number());
}

#[tokio::test]
async fn test_siem_exporters_endpoint() {
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/api/v1/siem/exporters", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("enabled").is_some());
    assert!(body.get("exporters").is_some());
}

#[tokio::test]
async fn test_check_file_access_allowed() {
    let (client, url) = test_setup();
    let resp = client
        .post(format!("{}/api/v1/check", url))
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/app/src/main.rs"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], true);
}

#[tokio::test]
async fn test_check_file_access_blocked() {
    let (client, url) = test_setup();
    let resp = client
        .post(format!("{}/api/v1/check", url))
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/home/user/.ssh/id_rsa"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], false);
}

#[tokio::test]
async fn test_check_egress_allowed() {
    let (client, url) = test_setup();
    let resp = client
        .post(format!("{}/api/v1/check", url))
        .json(&serde_json::json!({
            "action_type": "egress",
            "target": "api.openai.com:443"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], true);
}

#[tokio::test]
async fn test_get_policy() {
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/api/v1/policy", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let policy: serde_json::Value = resp.json().await.unwrap();
    assert!(policy["name"].is_string());
    assert!(policy["yaml"].is_string());
    assert!(policy["policy_hash"].is_string());
}

#[tokio::test]
async fn test_update_policy_bundle_rejects_policy_hash_mismatch() {
    let (client, url) = test_setup();

    let signer = hush_core::Keypair::generate();
    let policy = clawdstrike::Policy::new();
    let correct_hash = clawdstrike::PolicyBundle::new(policy.clone())
        .unwrap()
        .policy_hash;
    let bad_hash = {
        let mut bytes = *correct_hash.as_bytes();
        bytes[0] ^= 0x01;
        hush_core::Hash::from_bytes(bytes)
    };

    let bundle = clawdstrike::PolicyBundle {
        version: clawdstrike::POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: "test-bundle".to_string(),
        compiled_at: chrono::Utc::now().to_rfc3339(),
        policy,
        policy_hash: bad_hash,
        sources: Vec::new(),
        metadata: None,
    };
    let signed = clawdstrike::SignedPolicyBundle::sign_with_public_key(bundle, &signer).unwrap();

    let resp = client
        .put(format!("{}/api/v1/policy/bundle", url))
        .json(&signed)
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_audit_query() {
    let (client, url) = test_setup();

    // First, make some actions to audit
    client
        .post(format!("{}/api/v1/check", &url))
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to check action");

    // Query audit log
    let resp = client
        .get(format!("{}/api/v1/audit?limit=10", &url))
        .send()
        .await
        .expect("Failed to query audit");

    assert!(resp.status().is_success());

    let audit: serde_json::Value = resp.json().await.unwrap();
    assert!(audit["events"].is_array());
    assert!(audit["total"].is_number());
}

#[tokio::test]
async fn test_audit_encryption_stores_ciphertext_and_decrypts_on_query() {
    let key_path =
        std::env::temp_dir().join(format!("hushd-audit-key-{}.hex", uuid::Uuid::new_v4()));
    std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();

    let daemon = common::TestDaemon::spawn_with_config(Config {
        cors_enabled: false,
        rate_limit: RateLimitConfig {
            enabled: false,
            ..Default::default()
        },
        audit: AuditConfig {
            encryption: AuditEncryptionConfig {
                enabled: true,
                key_source: AuditEncryptionKeySource::File,
                key_path: Some(key_path),
                ..Default::default()
            },
        },
        ..Default::default()
    });

    let client = reqwest::Client::new();
    let url = daemon.url.clone();

    // Trigger an event with metadata (SecretLeakGuard emits details).
    client
        .post(format!("{}/api/v1/check", url))
        .json(&serde_json::json!({
            "action_type": "file_write",
            "target": "/tmp/out.txt",
            "content": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }))
        .send()
        .await
        .expect("Failed to check action");

    // Query audit log: should return decrypted metadata.
    let resp = client
        .get(format!("{}/api/v1/audit?limit=10", url))
        .send()
        .await
        .expect("Failed to query audit");
    assert!(resp.status().is_success());

    let audit: serde_json::Value = resp.json().await.unwrap();
    let events = audit["events"].as_array().unwrap();
    let violation = events
        .iter()
        .find(|e| e["decision"] == "blocked")
        .expect("expected at least one blocked event");
    assert!(violation.get("metadata").is_some());

    // Verify ciphertext is stored in SQLite (metadata_enc present, metadata NULL).
    let db_path = daemon.test_dir.join("audit.db");
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let (plain, enc): (Option<String>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT metadata, metadata_enc FROM audit_events WHERE decision = 'blocked' LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(plain.is_none());
    assert!(enc.is_some());
}

#[tokio::test]
async fn test_audit_stats() {
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/api/v1/audit/stats", url))
        .send()
        .await
        .expect("Failed to get audit stats");

    assert!(resp.status().is_success());

    let stats: serde_json::Value = resp.json().await.unwrap();
    assert!(stats["total_events"].is_number());
    assert!(stats["violations"].is_number());
    assert!(stats["allowed"].is_number());
}

#[tokio::test]
async fn test_sse_events() {
    let (client, url) = test_setup();

    // Start listening to events
    let resp = client
        .get(format!("{}/api/v1/events", url))
        .send()
        .await
        .expect("Failed to connect to events");

    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or("")),
        Some("text/event-stream")
    );
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/metrics", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("hushd_uptime_seconds"));
    assert!(body.contains("hushd_http_requests_total"));
    assert!(body.contains("hushd_siem_enabled"));
}

#[tokio::test]
async fn test_eval_policy_event() {
    let (client, url) = test_setup();

    let resp = client
        .post(format!("{}/api/v1/eval", url))
        .json(&serde_json::json!({
            "event": {
                "eventId": "evt-eval-1",
                "eventType": "tool_call",
                "timestamp": "2026-02-03T00:00:20Z",
                "sessionId": "sess-eval-1",
                "data": {
                    "type": "tool",
                    "toolName": "mcp__blender__execute_blender_code",
                    "parameters": { "code": "print('hello from mcp')" }
                },
                "metadata": { "toolKind": "mcp" }
            }
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["command"], "policy_eval");
    assert_eq!(json["decision"]["allowed"], true);
    assert_eq!(json["decision"]["denied"], false);
    assert_eq!(json["decision"]["warn"], false);
    assert_eq!(json["report"]["overall"]["allowed"], true);
}

#[tokio::test]
async fn test_v1_certification_lifecycle_basic() {
    let (client, url) = test_setup();

    // Create a certification (auth is disabled in integration harness by default).
    let resp = client
        .post(format!("{}/v1/certifications", url))
        .json(&serde_json::json!({
            "subject": {
                "type": "agent",
                "id": "agent_test_1",
                "name": "test-agent",
                "organizationId": "org_test"
            },
            "tier": "silver",
            "frameworks": ["soc2"],
            "policy": { "hash": "sha256:deadbeef", "version": "1.0.0", "ruleset": "clawdstrike:strict" },
            "validityDays": 30
        }))
        .send()
        .await
        .expect("Failed to create certification");

    assert!(resp.status().is_success());
    let created: serde_json::Value = resp.json().await.unwrap();
    let cert_id = created["data"]["certificationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Fetch certification.
    let resp = client
        .get(format!("{}/v1/certifications/{}", url, cert_id))
        .send()
        .await
        .expect("Failed to get certification");
    assert!(resp.status().is_success());
    let got: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        got["data"]["certificationId"].as_str(),
        Some(cert_id.as_str())
    );

    // Verify certification.
    let resp = client
        .post(format!("{}/v1/certifications/{}/verify", url, cert_id))
        .json(&serde_json::json!({
            "verificationContext": {
                "requiredTier": "certified",
                "checkRevocation": true,
                "checkExpiry": true
            }
        }))
        .send()
        .await
        .expect("Failed to verify certification");
    assert!(resp.status().is_success());
    let verified: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(verified["data"]["valid"], true);

    // Badge (SVG).
    let resp = client
        .get(format!("{}/v1/certifications/{}/badge", url, cert_id))
        .header("accept", "image/svg+xml")
        .send()
        .await
        .expect("Failed to get badge");
    assert!(resp.status().is_success());
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.contains("image/svg+xml"));

    // Badge (Accept negotiation): prefer SVG over PNG when both are accepted.
    let resp = client
        .get(format!("{}/v1/certifications/{}/badge", url, cert_id))
        .header("accept", "image/svg+xml, image/png, */*")
        .send()
        .await
        .expect("Failed to get badge (Accept negotiation)");
    assert!(resp.status().is_success());
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.contains("image/svg+xml"));

    // Badge (explicit format): PNG is not implemented yet.
    let resp = client
        .get(format!(
            "{}/v1/certifications/{}/badge?format=png",
            url, cert_id
        ))
        .send()
        .await
        .expect("Failed to get badge (format=png)");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_IMPLEMENTED);

    // Revoke certification.
    let resp = client
        .post(format!("{}/v1/certifications/{}/revoke", url, cert_id))
        .json(&serde_json::json!({ "reason": "security_incident", "details": "test" }))
        .send()
        .await
        .expect("Failed to revoke certification");
    assert!(resp.status().is_success());

    // Revocation status.
    let resp = client
        .get(format!("{}/v1/certifications/{}/revocation", url, cert_id))
        .send()
        .await
        .expect("Failed to get revocation status");
    assert!(resp.status().is_success());
    let rev: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(rev["data"]["revoked"], true);
}

#[tokio::test]
async fn test_v1_evidence_export_roundtrip() {
    let (client, url) = test_setup();

    // Create certification.
    let resp = client
        .post(format!("{}/v1/certifications", url))
        .json(&serde_json::json!({
            "subject": { "type": "agent", "id": "agent_test_2", "name": "test-agent-2", "organizationId": "org_test" },
            "tier": "certified",
            "frameworks": ["soc2"],
            "policy": { "hash": "sha256:deadbeef", "version": "1.0.0" },
            "validityDays": 30
        }))
        .send()
        .await
        .expect("Failed to create certification");
    assert!(resp.status().is_success());
    let created: serde_json::Value = resp.json().await.unwrap();
    let cert_id = created["data"]["certificationId"]
        .as_str()
        .unwrap()
        .to_string();

    // Export evidence (will likely be empty in tests, but should still produce a signed bundle).
    let resp = client
        .post(format!(
            "{}/v1/certifications/{}/evidence/export",
            url, cert_id
        ))
        .json(&serde_json::json!({
            "format": "zip",
            "dateRange": { "start": "2026-02-01T00:00:00Z", "end": "2026-02-04T00:00:00Z" },
            "includeTypes": ["audit_log"],
            "complianceTemplate": "soc2"
        }))
        .send()
        .await
        .expect("Failed to start evidence export");
    assert!(resp.status().is_success());
    let started: serde_json::Value = resp.json().await.unwrap();
    let export_id = started["data"]["exportId"].as_str().unwrap().to_string();

    // Poll for completion (should be quick).
    let mut status = serde_json::Value::Null;
    for _ in 0..50 {
        let resp = client
            .get(format!("{}/v1/evidence-exports/{}", url, export_id))
            .send()
            .await
            .expect("Failed to poll export status");
        assert!(resp.status().is_success());
        status = resp.json().await.unwrap();
        if status["data"]["status"] == "completed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert_eq!(status["data"]["status"], "completed");
    let download_url = status["data"]["downloadUrl"].as_str().unwrap();
    assert!(download_url.contains(&export_id));

    // Download bundle.
    let resp = client
        .get(format!("{}{}", url, download_url))
        .send()
        .await
        .expect("Failed to download evidence export");
    assert!(resp.status().is_success());
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.contains("application/zip"));
    let bytes = resp.bytes().await.unwrap();
    assert!(!bytes.is_empty());
}

#[tokio::test]
async fn test_v1_webhooks_delivery_on_certification_issued() {
    use axum::{routing::post, Router};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let (client, url) = test_setup();

    // Local webhook receiver.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hook_url = format!("http://{}/hook", addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
    let tx = Arc::new(Mutex::new(Some(tx)));

    let app = Router::new().route(
        "/hook",
        post({
            let tx = tx.clone();
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let tx = tx.clone();
                async move {
                    assert!(headers.get("x-clawdstrike-event").is_some());
                    assert!(headers.get("x-clawdstrike-signature").is_some());
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(json);
                    }
                    axum::http::StatusCode::OK
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Register webhook.
    let resp = client
        .post(format!("{}/v1/webhooks", url))
        .json(&serde_json::json!({
            "url": hook_url,
            "events": ["certification.issued"],
            "secret": "secret",
            "enabled": true
        }))
        .send()
        .await
        .expect("Failed to create webhook");
    assert!(resp.status().is_success());

    // Trigger event.
    let resp = client
        .post(format!("{}/v1/certifications", url))
        .json(&serde_json::json!({
            "subject": { "type": "agent", "id": "agent_webhook", "name": "webhook-agent", "organizationId": "org_test" },
            "tier": "certified",
            "frameworks": ["soc2"],
            "policy": { "hash": "sha256:deadbeef", "version": "1.0.0" },
            "validityDays": 30
        }))
        .send()
        .await
        .expect("Failed to create certification");
    assert!(resp.status().is_success());

    // Wait for webhook delivery.
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("Timed out waiting for webhook")
        .expect("Webhook channel closed");

    assert_eq!(received["event"], "certification.issued");
    assert!(received["data"]["certificationId"].is_string());
}
// Unit tests that don't require daemon
#[test]
fn test_config_default() {
    let config = hushd::config::Config::default();
    assert_eq!(config.listen, "127.0.0.1:9876");
    assert_eq!(config.ruleset, "default");
}

#[test]
fn test_config_tracing_level() {
    let config = hushd::config::Config {
        log_level: "debug".to_string(),
        ..Default::default()
    };
    assert_eq!(config.tracing_level(), tracing::Level::DEBUG);
}

// Auth tests - these require auth to be enabled on the daemon

#[tokio::test]
async fn test_auth_required_without_token() {
    let (daemon, _keys) = common::TestDaemon::spawn_auth_daemon();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/check", daemon.url))
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_with_valid_token() {
    let (daemon, keys) = common::TestDaemon::spawn_auth_daemon();
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/check", daemon.url))
        .header("Authorization", format!("Bearer {}", keys.check_key))
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
}

#[tokio::test]
async fn test_auth_with_invalid_token() {
    let (daemon, _keys) = common::TestDaemon::spawn_auth_daemon();
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/check", daemon.url))
        .header("Authorization", "Bearer invalid-key-12345")
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_endpoint_requires_admin_scope() {
    let (daemon, keys) = common::TestDaemon::spawn_auth_daemon();
    let client = reqwest::Client::new();
    let url = daemon.url.clone();

    // The check-only key should be forbidden from admin endpoints
    let resp = client
        .post(format!("{}/api/v1/policy/reload", url))
        .header("Authorization", format!("Bearer {}", keys.check_key))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    let resp = client
        .post(format!("{}/api/v1/policy/reload", url))
        .header("Authorization", format!("Bearer {}", keys.admin_key))
        .send()
        .await
        .expect("Failed to connect to daemon");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_health_always_public() {
    let (daemon, _keys) = common::TestDaemon::spawn_auth_daemon();
    let client = reqwest::Client::new();
    let url = daemon.url.clone();
    let resp = client
        .get(format!("{}/health", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
}

// Rate limiting tests - spawn a dedicated daemon with low burst size

#[tokio::test]
async fn test_rate_limiting_returns_429() {
    let daemon = common::TestDaemon::spawn_rate_limited_daemon(3, 1);
    let client = reqwest::Client::new();

    // Make requests until we hit the rate limit
    let mut hit_limit = false;
    for _ in 0..20 {
        let resp = client
            .post(format!("{}/api/v1/check", daemon.url))
            .json(&serde_json::json!({
                "action_type": "file_access",
                "target": "/test/file.txt"
            }))
            .send()
            .await
            .expect("Failed to connect to daemon");

        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            hit_limit = true;
            // Verify Retry-After header is present
            assert!(resp.headers().contains_key("retry-after"));
            break;
        }
    }

    assert!(hit_limit, "Expected to hit rate limit within 20 requests");
}

#[tokio::test]
async fn test_health_not_rate_limited() {
    let daemon = common::TestDaemon::spawn_rate_limited_daemon(3, 1);
    let client = reqwest::Client::new();
    let url = daemon.url.clone();

    // Health endpoint should never be rate limited
    // Make many requests quickly
    for _ in 0..20 {
        let resp = client
            .get(format!("{}/health", url))
            .send()
            .await
            .expect("Failed to connect to daemon");

        assert!(
            resp.status().is_success(),
            "Health endpoint should never return 429"
        );
    }
}
