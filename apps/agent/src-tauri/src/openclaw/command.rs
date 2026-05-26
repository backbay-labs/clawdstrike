//! Invocation of the `openclaw` external binary with JSON output parsing.

use anyhow::Result;
use serde_json::Value;

pub(super) fn extract_json_payload(output: &str) -> Result<Value> {
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
            Some(Err(err)) => {
                last_error = Some(format!("Failed to parse OpenClaw JSON: {}", err));
            }
            None => {}
        }
    }

    if let Some((value, _)) = best {
        return Ok(value);
    }

    Err(anyhow::anyhow!(last_error.unwrap_or_else(|| {
        if saw_candidate {
            "Failed to parse OpenClaw JSON".to_string()
        } else {
            "OpenClaw returned no JSON payload".to_string()
        }
    })))
}

pub(super) async fn run_openclaw_json(args: Vec<String>) -> Result<Value> {
    let output = tokio::task::spawn_blocking(move || {
        let mut full_args = vec!["--no-color".to_string()];
        full_args.extend(args);

        std::process::Command::new("openclaw")
            .args(full_args)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute openclaw: {}", e))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to join openclaw task: {}", e))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow::anyhow!(
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
