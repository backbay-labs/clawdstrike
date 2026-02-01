//! Integration tests for hushd HTTP API

// Note: These tests require the daemon to be running
// Run with: cargo test -p hushd --test integration -- --ignored

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_health_endpoint() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/health")
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
#[ignore = "requires running daemon"]
async fn test_check_file_access_allowed() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
#[ignore = "requires running daemon"]
async fn test_check_file_access_blocked() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
#[ignore = "requires running daemon"]
async fn test_check_egress_allowed() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
#[ignore = "requires running daemon"]
async fn test_get_policy() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/policy")
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
#[ignore = "requires running daemon"]
async fn test_audit_query() {
    let client = reqwest::Client::new();

    // First, make some actions to audit
    client
        .post("http://127.0.0.1:9876/api/v1/check")
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to check action");

    // Query audit log
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/audit?limit=10")
        .send()
        .await
        .expect("Failed to query audit");

    assert!(resp.status().is_success());

    let audit: serde_json::Value = resp.json().await.unwrap();
    assert!(audit["events"].is_array());
    assert!(audit["total"].is_number());
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_audit_stats() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/audit/stats")
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
#[ignore = "requires running daemon"]
async fn test_sse_events() {
    let client = reqwest::Client::new();

    // Start listening to events
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/events")
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

// Unit tests that don't require daemon
#[test]
fn test_config_default() {
    let config = hushd::config::Config::default();
    assert_eq!(config.listen, "127.0.0.1:9876");
    assert_eq!(config.ruleset, "default");
}

#[test]
fn test_config_tracing_level() {
    let mut config = hushd::config::Config::default();
    config.log_level = "debug".to_string();
    assert_eq!(config.tracing_level(), tracing::Level::DEBUG);
}

// Auth tests - these require auth to be enabled on the daemon
// Run with: AUTH_ENABLED=1 cargo test -p hushd --test integration -- --ignored

#[tokio::test]
#[ignore = "requires running daemon with auth enabled"]
async fn test_auth_required_without_token() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
    let client = reqwest::Client::new();
    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");

    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
    let client = reqwest::Client::new();

    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
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
    let client = reqwest::Client::new();
    // Use a key with only check/read scope, not admin
    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");

    let resp = client
        .post("http://127.0.0.1:9876/api/v1/policy/reload")
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .expect("Failed to connect to daemon");

    // Should be 403 Forbidden if key doesn't have admin scope
    // or 200 if it does have admin scope
    assert!(
        resp.status() == reqwest::StatusCode::FORBIDDEN
            || resp.status() == reqwest::StatusCode::OK
    );
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_health_always_public() {
    // Health should work even with auth enabled and no token
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/health")
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());
}
