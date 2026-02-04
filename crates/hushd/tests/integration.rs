//! Integration tests for hushd HTTP API
//!
//! These tests require either:
//! 1. A running daemon at HUSHD_TEST_URL (for local development)
//! 2. The daemon binary at HUSHD_BIN (for CI, will spawn automatically)

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
    assert!(body.contains("hushd_http_requests_total"));
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
// Run with: HUSHD_TEST_AUTH_ENABLED=1 cargo test -p hushd --test integration

#[tokio::test]
#[ignore = "requires running daemon with auth enabled"]
async fn test_auth_required_without_token() {
    let (client, url) = test_setup();
    let resp = client
        .post(format!("{}/api/v1/check", url))
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
#[ignore = "requires running daemon with auth enabled"]
async fn test_auth_with_valid_token() {
    let (client, url) = test_setup();
    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");

    let resp = client
        .post(format!("{}/api/v1/check", url))
        .header("Authorization", format!("Bearer {}", api_key))
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
#[ignore = "requires running daemon with auth enabled"]
async fn test_auth_with_invalid_token() {
    let (client, url) = test_setup();

    let resp = client
        .post(format!("{}/api/v1/check", url))
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
#[ignore = "requires running daemon with auth enabled"]
async fn test_admin_endpoint_requires_admin_scope() {
    let (client, url) = test_setup();
    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");

    let resp = client
        .post(format!("{}/api/v1/policy/reload", url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .expect("Failed to connect to daemon");

    // Should be 403 Forbidden if key doesn't have admin scope
    // or 200 if it does have admin scope
    assert!(
        resp.status() == reqwest::StatusCode::FORBIDDEN || resp.status() == reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_health_always_public() {
    // Health should work even with auth enabled and no token
    let (client, url) = test_setup();
    let resp = client
        .get(format!("{}/health", url))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
}

// Rate limiting tests
// Note: These tests require the daemon to have rate limiting enabled with low limits

#[tokio::test]
#[ignore = "requires daemon with rate_limit.burst_size = 3"]
async fn test_rate_limiting_returns_429() {
    let (client, url) = test_setup();

    // Make requests until we hit the rate limit
    let mut hit_limit = false;
    for _ in 0..10 {
        let resp = client
            .post(format!("{}/api/v1/check", url))
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

    assert!(hit_limit, "Expected to hit rate limit within 10 requests");
}

#[tokio::test]
async fn test_health_not_rate_limited() {
    let (client, url) = test_setup();

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
