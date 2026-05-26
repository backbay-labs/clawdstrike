use super::types::normalize_policy_check_input;
use super::*;
use crate::settings::Settings;
use axum::{http::StatusCode, routing::post, Router};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[test]
fn normalizes_action_type_aliases() {
    let input = PolicyCheckInput {
        action_type: "exec".to_string(),
        target: "echo hi".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "shell");

    let input = PolicyCheckInput {
        action_type: "network".to_string(),
        target: "example.com".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "egress");
    assert_eq!(normalized.target, "example.com");

    let input = PolicyCheckInput {
        action_type: "MCP_TOOL".to_string(),
        target: "tool".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "mcp_tool");

    let input = PolicyCheckInput {
        action_type: "CUSTOM_ACTION".to_string(),
        target: "x".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "custom_action");
}

#[test]
fn normalizes_file_alias_to_access_vs_write() {
    let input = PolicyCheckInput {
        action_type: "file".to_string(),
        target: "/tmp/a.txt".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "file_access");

    let input = PolicyCheckInput {
        action_type: "file".to_string(),
        target: "/tmp/a.txt".to_string(),
        content: Some("hello".to_string()),
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "file_write");
}

#[test]
fn normalizes_egress_url_target_to_host_port() {
    let input = PolicyCheckInput {
        action_type: "egress".to_string(),
        target: "https://example.com/foo".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "egress");
    assert_eq!(normalized.target, "example.com:443");

    let input = PolicyCheckInput {
        action_type: "network".to_string(),
        target: "http://example.com:8080/path".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.action_type, "egress");
    assert_eq!(normalized.target, "example.com:8080");
}

#[test]
fn normalizes_egress_ipv6_url_target_to_bracketed_host_port() {
    let input = PolicyCheckInput {
        action_type: "egress".to_string(),
        target: "https://[::1]:8443/".to_string(),
        content: None,
        args: None,
        agent_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        runtime_agent_kind: None,
    };
    let normalized = normalize_policy_check_input(input);
    assert_eq!(normalized.target, "[::1]:8443");
}

async fn start_test_check_server(status: StatusCode, body: &'static str) -> u16 {
    let app = Router::new().route("/api/v1/check", post(move || async move { (status, body) }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn daemon_error_body_is_omitted_by_default() {
    let port = start_test_check_server(StatusCode::BAD_REQUEST, "SENSITIVE_INTERNAL_ERROR").await;

    let mut s = Settings::default();
    s.daemon_port = port;
    s.enabled = true;
    s.debug_include_daemon_error_body = false;
    let settings = Arc::new(RwLock::new(s));

    let out = evaluate_policy_check(
        settings,
        &reqwest::Client::new(),
        PolicyCheckInput {
            action_type: "file_access".to_string(),
            target: "/tmp/a.txt".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        },
        None,
        None,
    )
    .await;

    assert!(!out.allowed);
    let details = out.details.expect("details should be present");
    assert!(details.get("http_status").is_some());
    assert!(details.get("body").is_none());
    assert!(details.get("body_truncated").is_none());
    assert_eq!(out.guard.as_deref(), Some("policy_request_error"));
}

#[tokio::test]
async fn daemon_error_body_is_included_when_debug_enabled() {
    let port = start_test_check_server(StatusCode::BAD_REQUEST, "SENSITIVE_INTERNAL_ERROR").await;

    let mut s = Settings::default();
    s.daemon_port = port;
    s.enabled = true;
    s.debug_include_daemon_error_body = true;
    let settings = Arc::new(RwLock::new(s));

    let out = evaluate_policy_check(
        settings,
        &reqwest::Client::new(),
        PolicyCheckInput {
            action_type: "file_access".to_string(),
            target: "/tmp/a.txt".to_string(),
            content: None,
            args: None,
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
        },
        None,
        None,
    )
    .await;

    assert!(!out.allowed);
    let details = out.details.expect("details should be present");
    assert_eq!(
        details.get("http_status").and_then(|v| v.as_u64()),
        Some(400)
    );
    assert_eq!(
        details.get("body").and_then(|v| v.as_str()),
        Some("SENSITIVE_INTERNAL_ERROR")
    );
    assert_eq!(
        details.get("body_truncated").and_then(|v| v.as_bool()),
        Some(false)
    );
}
