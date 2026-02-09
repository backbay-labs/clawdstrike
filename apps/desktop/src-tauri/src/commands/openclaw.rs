//! OpenClaw CLI helpers for the desktop UI.
//!
//! We keep discovery/probe logic in Rust so the webview can stay a native WS
//! client and still access OS-level tailnet/discovery data via Tauri IPC.

use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use super::extract_json_payload;
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
}
