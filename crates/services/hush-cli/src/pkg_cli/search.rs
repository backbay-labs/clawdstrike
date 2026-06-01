//! `pkg search` — query the registry and print a results table.

use std::io::Write;

use super::util::{truncate_with_ellipsis, urlencoding_simple};
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

pub(super) fn cmd_pkg_search(
    query: &str,
    limit: usize,
    page: usize,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let offset = page * limit;
    let url = format!(
        "{}/api/v1/search?q={}&limit={}&offset={}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(query),
        limit,
        offset
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: search request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let results = match resp_json.get("packages").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => {
            let _ = writeln!(stdout, "No packages found.");
            return ExitCode::Ok;
        }
    };

    if results.is_empty() {
        let _ = writeln!(stdout, "No packages found.");
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "{:<40} {:<12} DESCRIPTION", "NAME", "VERSION");
    let _ = writeln!(stdout, "{}", "-".repeat(80));

    for result in results {
        let name = result.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let version = result
            .get("latest_version")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let description = result
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let desc_display = truncate_with_ellipsis(description, 37);
        let _ = writeln!(stdout, "{:<40} {:<12} {}", name, version, desc_display);
    }

    let total = resp_json
        .get("total")
        .and_then(|t| t.as_u64())
        .unwrap_or(results.len() as u64);
    let showing_end = offset + results.len();
    let _ = writeln!(
        stdout,
        "\nShowing {}-{} of {} results",
        offset + 1,
        showing_end,
        total
    );

    ExitCode::Ok
}
