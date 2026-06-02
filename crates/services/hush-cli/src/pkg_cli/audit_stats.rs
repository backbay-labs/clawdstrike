//! `pkg audit` and `pkg stats` — registry publish-history and download
//! statistics reports.

use std::io::Write;

use super::util::{format_number, urlencoding_simple};
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

// ---------------------------------------------------------------------------
// pkg audit
// ---------------------------------------------------------------------------

pub(super) fn cmd_pkg_audit(
    name: &str,
    registry: Option<&str>,
    limit: u32,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/audit/{}?limit={}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        limit
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
            let _ = writeln!(stderr, "Error: audit request failed: {e}");
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

    let events = match resp_json.get("events").and_then(|e| e.as_array()) {
        Some(e) => e,
        None => {
            let _ = writeln!(stdout, "No audit events found for '{}'.", name);
            return ExitCode::Ok;
        }
    };

    if events.is_empty() {
        let _ = writeln!(stdout, "No audit events found for '{}'.", name);
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Audit log for: {}\n", name);
    let _ = writeln!(
        stdout,
        "{:<12} {:<10} {:<20} PUBLISHER KEY",
        "VERSION", "ACTION", "TIMESTAMP"
    );
    let _ = writeln!(stdout, "{}", "-".repeat(72));

    for event in events {
        let version = event.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let action = event.get("action").and_then(|a| a.as_str()).unwrap_or("?");
        let timestamp = event
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("?");
        let publisher_key = event
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let key_display = if publisher_key.len() > 16 {
            format!("{}...", &publisher_key[..16])
        } else {
            publisher_key.to_string()
        };

        let _ = writeln!(
            stdout,
            "{:<12} {:<10} {:<20} {}",
            version, action, timestamp, key_display
        );
    }

    let _ = writeln!(stdout, "\n{} event(s) shown.", events.len());
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg stats
// ---------------------------------------------------------------------------

pub(super) fn cmd_pkg_stats(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/packages/{}/stats",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
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
            let _ = writeln!(stderr, "Error: stats request failed: {e}");
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

    let pkg_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(name);
    let total_downloads = resp_json
        .get("total_downloads")
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let first_published = resp_json
        .get("first_published")
        .and_then(|f| f.as_str())
        .unwrap_or("unknown");

    let _ = writeln!(stdout, "Package: {}", pkg_name);
    let _ = writeln!(
        stdout,
        "Total downloads: {}",
        format_number(total_downloads)
    );
    let _ = writeln!(stdout, "First published: {}", first_published);

    let versions = resp_json.get("versions").and_then(|v| v.as_array());

    if let Some(versions) = versions {
        if !versions.is_empty() {
            let _ = writeln!(stdout);
            let _ = writeln!(stdout, "  {:<12} {:<12} PUBLISHED", "VERSION", "DOWNLOADS");
            let _ = writeln!(stdout, "  {}", "-".repeat(50));

            for v in versions {
                let version = v.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let downloads = v.get("downloads").and_then(|d| d.as_u64()).unwrap_or(0);
                let published_at = v
                    .get("published_at")
                    .and_then(|p| p.as_str())
                    .unwrap_or("?");
                let _ = writeln!(
                    stdout,
                    "  {:<12} {:<12} {}",
                    version,
                    format_number(downloads),
                    published_at
                );
            }
        }
    }

    ExitCode::Ok
}
