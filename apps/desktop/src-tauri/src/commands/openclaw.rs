//! OpenClaw CLI helpers for the desktop UI.
//!
//! We keep discovery/probe logic in Rust so the webview can stay a native WS
//! client and still access OS-level tailnet/discovery data via Tauri IPC.

use serde_json::Value;
use std::path::PathBuf;

fn clawdstrike_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

fn read_agent_api_port() -> u16 {
    let settings_path = clawdstrike_config_dir().join("agent.json");
    let Ok(raw) = std::fs::read_to_string(settings_path) else {
        return 9878;
    };
    let Ok(json) = serde_json::from_str::<Value>(&raw) else {
        return 9878;
    };
    json.get("agent_api_port")
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(9878)
}

fn read_agent_api_token() -> Result<String, String> {
    for env_key in [
        "CLAWDSTRIKE_AGENT_API_TOKEN",
        "SDR_AGENT_API_TOKEN",
        "OPENCLAW_AGENT_API_TOKEN",
        "VITE_AGENT_API_TOKEN",
    ] {
        if let Ok(raw) = std::env::var(env_key) {
            let token = raw.trim().to_string();
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }

    let token_path = clawdstrike_config_dir().join("agent-local-token");
    let raw = std::fs::read_to_string(&token_path)
        .map_err(|e| format!("Failed to read {:?}: {}", token_path, e))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(format!("Agent token file {:?} is empty", token_path));
    }
    Ok(token)
}

fn is_expected_agent_unavailable_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    (lower.contains("failed to read") && lower.contains("agent-local-token"))
        || lower.contains("connection refused")
        || lower.contains("failed to connect")
        || lower.contains("tcp connect error")
        || lower.contains("timed out")
        || lower.contains("os error 61")
        || lower.contains("os error 111")
}

fn direct_mode_enabled() -> bool {
    cfg!(debug_assertions)
        && (std::env::var("SDR_OPENCLAW_DIRECT_MODE").ok().as_deref() == Some("1")
            || std::env::var("VITE_OPENCLAW_DIRECT_MODE").ok().as_deref() == Some("1"))
}

fn agent_base_url() -> String {
    format!("http://127.0.0.1:{}", read_agent_api_port())
}

fn normalize_allowed_agent_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Missing agent API path".to_string());
    }
    if !trimmed.starts_with('/') {
        return Err("Agent API path must start with '/'".to_string());
    }
    if trimmed.contains("://") {
        return Err("Agent API path must be relative".to_string());
    }
    if trimmed.contains('\\') {
        return Err("Agent API path must not contain backslashes".to_string());
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err("Agent API path must not include query or fragment".to_string());
    }
    if trimmed != "/" && trimmed.ends_with('/') {
        return Err("Agent API path must not end with '/'".to_string());
    }

    let raw_segments: Vec<&str> = trimmed.trim_start_matches('/').split('/').collect();
    if raw_segments.is_empty() || raw_segments.iter().any(|segment| segment.is_empty()) {
        return Err("Agent API path must not contain empty segments".to_string());
    }

    for segment in &raw_segments {
        if *segment == "." || *segment == ".." {
            return Err("Agent API path must not contain dot segments".to_string());
        }

        let lower = segment.to_ascii_lowercase();
        if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
            return Err(
                "Agent API path must not contain encoded dot or separator segments".to_string(),
            );
        }
    }

    if !is_allowed_agent_path_segments(&raw_segments) {
        return Err(format!("Disallowed agent API path: {trimmed}"));
    }

    Ok(format!("/{}", raw_segments.join("/")))
}

fn is_allowed_agent_path_segments(segments: &[&str]) -> bool {
    match segments {
        ["api", "v1", "openclaw", "gateways"]
        | ["api", "v1", "openclaw", "active-gateway"]
        | ["api", "v1", "openclaw", "discover"]
        | ["api", "v1", "openclaw", "probe"]
        | ["api", "v1", "openclaw", "request"]
        | ["api", "v1", "openclaw", "import-desktop-gateways"] => true,
        ["api", "v1", "openclaw", "gateways", gateway_id] => !gateway_id.is_empty(),
        ["api", "v1", "openclaw", "gateways", gateway_id, action] => {
            !gateway_id.is_empty() && matches!(*action, "connect" | "disconnect")
        }
        _ => false,
    }
}

fn parse_request_method(method: &str) -> Result<reqwest::Method, String> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "POST" => Ok(reqwest::Method::POST),
        "PATCH" => Ok(reqwest::Method::PATCH),
        "PUT" => Ok(reqwest::Method::PUT),
        "DELETE" => Ok(reqwest::Method::DELETE),
        _ => Err(format!("Unsupported method: {}", method)),
    }
}

async fn call_agent_endpoint(
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, String> {
    let normalized_path = normalize_allowed_agent_path(path)?;
    let token = read_agent_api_token()?;
    let url = format!("{}{}", agent_base_url(), normalized_path);

    let client = reqwest::Client::new();
    let mut request = client
        .request(method, &url)
        .header("Authorization", format!("Bearer {}", token));

    if let Some(payload) = body {
        request = request.json(payload);
    }

    let response = request.send().await.map_err(|e| {
        format!(
            "Agent OpenClaw request failed for {}: {}",
            normalized_path, e
        )
    })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Agent OpenClaw endpoint {} returned {}: {}",
            normalized_path, status, body
        ));
    }

    response
        .text()
        .await
        .map_err(|e| {
            format!(
                "Failed to read OpenClaw response for {}: {}",
                normalized_path, e
            )
        })
        .and_then(|raw| {
            if raw.trim().is_empty() {
                Ok(Value::Null)
            } else {
                serde_json::from_str::<Value>(&raw).map_err(|e| {
                    format!(
                        "Failed to parse OpenClaw response for {}: {}",
                        normalized_path, e
                    )
                })
            }
        })
}

async fn call_agent_openclaw_endpoint(
    path: &str,
    timeout_ms: Option<u64>,
) -> Result<Value, String> {
    call_agent_endpoint(
        reqwest::Method::POST,
        path,
        Some(&serde_json::json!({
            "timeout_ms": timeout_ms
        })),
    )
    .await
}

fn extract_json_payload(output: &str) -> Result<Value, String> {
    let mut saw_candidate = false;
    let mut best: Option<(Value, usize)> = None;
    let mut last_error: Option<String> = None;

    for (idx, ch) in output.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }
        saw_candidate = true;
        let json = &output[idx..];
        let deser = serde_json::Deserializer::from_str(json);
        let mut stream = deser.into_iter::<Value>();
        match stream.next() {
            Some(Ok(value)) => {
                let remainder = &json[stream.byte_offset()..];
                let remainder_len = remainder.trim().len();
                if remainder_len == 0 {
                    return Ok(value);
                }

                match &best {
                    Some((_, best_len)) if remainder_len >= *best_len => {}
                    _ => best = Some((value, remainder_len)),
                }
            }
            Some(Err(e)) => {
                last_error = Some(format!("Failed to parse OpenClaw JSON: {}", e));
            }
            None => {}
        }
    }

    if let Some((value, _)) = best {
        return Ok(value);
    }

    Err(last_error.unwrap_or_else(|| {
        if saw_candidate {
            "Failed to parse OpenClaw JSON".to_string()
        } else {
            "OpenClaw returned no JSON payload".to_string()
        }
    }))
}

async fn run_openclaw_json(args: Vec<String>) -> Result<Value, String> {
    let output = tokio::task::spawn_blocking(move || {
        let mut full_args = vec!["--no-color".to_string()];
        full_args.extend(args);

        std::process::Command::new("openclaw")
            .args(full_args)
            .output()
            .map_err(|e| format!("Failed to execute openclaw: {}", e))
    })
    .await
    .map_err(|e| format!("Failed to join openclaw task: {}", e))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "OpenClaw exited with {}: {}{}",
            output.status,
            stderr.trim(),
            if stderr.trim().is_empty() && !stdout.trim().is_empty() {
                format!(" (stdout: {})", stdout.trim())
            } else {
                "".to_string()
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_json_payload(&stdout)
}

#[tauri::command]
pub async fn openclaw_gateway_discover(timeout_ms: Option<u64>) -> Result<Value, String> {
    if !direct_mode_enabled() {
        match call_agent_openclaw_endpoint("/api/v1/openclaw/discover", timeout_ms).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if is_expected_agent_unavailable_error(&err) {
                    eprintln!(
                        "Agent OpenClaw discover unavailable, falling back to local CLI discover: {}",
                        err
                    );
                } else {
                    return Err(err);
                }
            }
        }
    }

    let mut args = vec![
        "gateway".to_string(),
        "discover".to_string(),
        "--json".to_string(),
    ];

    if let Some(timeout_ms) = timeout_ms {
        args.push("--timeout".to_string());
        args.push(timeout_ms.to_string());
    }

    run_openclaw_json(args).await
}

#[tauri::command]
pub async fn openclaw_gateway_probe(timeout_ms: Option<u64>) -> Result<Value, String> {
    if !direct_mode_enabled() {
        match call_agent_openclaw_endpoint("/api/v1/openclaw/probe", timeout_ms).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if is_expected_agent_unavailable_error(&err) {
                    eprintln!(
                        "Agent OpenClaw probe unavailable, falling back to local CLI probe: {}",
                        err
                    );
                } else {
                    return Err(err);
                }
            }
        }
    }

    let mut args = vec![
        "gateway".to_string(),
        "probe".to_string(),
        "--json".to_string(),
    ];

    if let Some(timeout_ms) = timeout_ms {
        args.push("--timeout".to_string());
        args.push(timeout_ms.to_string());
    }

    run_openclaw_json(args).await
}

#[tauri::command]
pub async fn openclaw_agent_request(
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<Value, String> {
    let parsed_method = parse_request_method(&method)?;
    call_agent_endpoint(parsed_method, &path, body.as_ref()).await
}

#[cfg(test)]
mod tests {
    use super::{
        extract_json_payload, is_expected_agent_unavailable_error, normalize_allowed_agent_path,
        parse_request_method,
    };
    use serde_json::json;

    #[test]
    fn extracts_clean_json_payload() {
        let value = extract_json_payload("{\"ok\":true}\n").expect("parse");
        assert_eq!(value, json!({ "ok": true }));
    }

    #[test]
    fn extracts_json_after_noise() {
        let value = extract_json_payload("warning: something\n{\"count\":1}\n").expect("parse");
        assert_eq!(value, json!({ "count": 1 }));
    }

    #[test]
    fn skips_invalid_candidates_and_finds_valid_json() {
        let value = extract_json_payload("note: {not json}\n{\"ok\":true}\n").expect("parse");
        assert_eq!(value, json!({ "ok": true }));
    }

    #[test]
    fn prefers_payload_closest_to_end() {
        let value =
            extract_json_payload("{\"log\":true} trailing\n{\"ok\":true}\n").expect("parse");
        assert_eq!(value, json!({ "ok": true }));
    }

    #[test]
    fn errors_when_no_json_payload_present() {
        let err = extract_json_payload("nothing to see here").expect_err("should error");
        assert!(err.contains("no JSON payload"));
    }

    #[test]
    fn allows_only_expected_agent_api_paths() {
        assert_eq!(
            normalize_allowed_agent_path("/api/v1/openclaw/gateways").expect("allowed"),
            "/api/v1/openclaw/gateways"
        );
        assert_eq!(
            normalize_allowed_agent_path("/api/v1/openclaw/gateways/demo/connect")
                .expect("allowed"),
            "/api/v1/openclaw/gateways/demo/connect"
        );
        assert_eq!(
            normalize_allowed_agent_path("/api/v1/openclaw/request").expect("allowed"),
            "/api/v1/openclaw/request"
        );
        assert_eq!(
            normalize_allowed_agent_path("/api/v1/openclaw/active-gateway").expect("allowed"),
            "/api/v1/openclaw/active-gateway"
        );
        assert!(normalize_allowed_agent_path("/api/v1/agent/settings").is_err());
        assert!(normalize_allowed_agent_path("/api/v1/agent/health").is_err());
        assert!(normalize_allowed_agent_path("/api/v1/daemon/restart").is_err());
    }

    #[test]
    fn rejects_traversal_and_noncanonical_agent_api_paths() {
        assert!(
            normalize_allowed_agent_path("/api/v1/openclaw/gateways/../../agent/settings").is_err()
        );
        assert!(normalize_allowed_agent_path("/api/v1/openclaw/gateways/%2e%2e/connect").is_err());
        assert!(normalize_allowed_agent_path("/api/v1/openclaw/gateways/%2Fetc%2Fpasswd").is_err());
        assert!(normalize_allowed_agent_path("/api/v1/openclaw/gateways//demo").is_err());
        assert!(normalize_allowed_agent_path("/api/v1/openclaw/gateways/demo?x=1").is_err());
        assert!(
            normalize_allowed_agent_path("http://127.0.0.1:9878/api/v1/openclaw/gateways").is_err()
        );
    }

    #[test]
    fn parses_supported_http_methods() {
        assert!(parse_request_method("get").is_ok());
        assert!(parse_request_method("POST").is_ok());
        assert!(parse_request_method("patch").is_ok());
        assert!(parse_request_method("put").is_ok());
        assert!(parse_request_method("delete").is_ok());
        assert!(parse_request_method("trace").is_err());
    }

    #[test]
    fn classifies_expected_agent_unavailable_errors() {
        assert!(is_expected_agent_unavailable_error(
            "Failed to read \"/tmp/agent-local-token\": No such file"
        ));
        assert!(is_expected_agent_unavailable_error(
            "Agent OpenClaw request failed for /api/v1/openclaw/probe: tcp connect error: Connection refused (os error 61)"
        ));
        assert!(!is_expected_agent_unavailable_error(
            "Agent OpenClaw endpoint /api/v1/openclaw/probe returned 401 unauthorized"
        ));
    }
}
