//! `pkg org` — organization management subcommands (create, members,
//! invite, remove, info).

use std::io::Write;

use super::auth::build_caller_auth_headers;
use super::util::urlencoding_simple;
use super::OrgCommands;
use crate::registry_config::{load_or_generate_publisher_keypair, RegistryConfig};
use crate::ExitCode;

pub(super) fn cmd_pkg_org(
    command: OrgCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        OrgCommands::Create {
            name,
            display_name,
            registry,
        } => cmd_org_create(
            &name,
            display_name.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Members { name, registry } => {
            cmd_org_members(&name, registry.as_deref(), stdout, stderr)
        }
        OrgCommands::Invite {
            org,
            publisher_key,
            role,
            registry,
        } => cmd_org_invite(
            &org,
            &publisher_key,
            &role,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Remove {
            org,
            publisher_key,
            registry,
        } => cmd_org_remove(&org, &publisher_key, registry.as_deref(), stdout, stderr),
        OrgCommands::Info { name, registry } => {
            cmd_org_info(&name, registry.as_deref(), stdout, stderr)
        }
    }
}

fn cmd_org_create(
    name: &str,
    display_name: Option<&str>,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

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

    let url = format!("{}/api/v1/orgs", cfg.registry_url.trim_end_matches('/'));

    let mut body = serde_json::json!({
        "name": name,
        "publisher_key": keypair.public_key().to_hex(),
    });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::Value::String(dn.to_string());
    }
    let payload = format!(
        "org:create:{}:{}:{}",
        name,
        keypair.public_key().to_hex(),
        display_name.unwrap_or("")
    );
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Created organization @{}", name);
    ExitCode::Ok
}

fn cmd_org_members(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

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

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).bearer_auth(&auth_token).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
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
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let members = match resp_json.get("members").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => {
            let _ = writeln!(stdout, "No members found.");
            return ExitCode::Ok;
        }
    };

    let _ = writeln!(stdout, "Members of @{}:\n", name);
    let _ = writeln!(stdout, "{:<48} {:<12} JOINED", "KEY", "ROLE");
    let _ = writeln!(stdout, "{}", "-".repeat(80));

    for member in members {
        let key = member
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let role = member.get("role").and_then(|r| r.as_str()).unwrap_or("?");
        let joined = member
            .get("joined_at")
            .and_then(|j| j.as_str())
            .unwrap_or("?");
        let key_display = if key.len() > 44 {
            format!("{}...", &key[..44])
        } else {
            key.to_string()
        };
        let _ = writeln!(stdout, "{:<48} {:<12} {}", key_display, role, joined);
    }

    let _ = writeln!(stdout, "\n{} member(s)", members.len());
    ExitCode::Ok
}

fn cmd_org_invite(
    org: &str,
    publisher_key: &str,
    role: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if !matches!(role, "owner" | "maintainer" | "member") {
        let _ = writeln!(
            stderr,
            "Error: invalid role '{}'. Must be one of: owner, maintainer, member",
            role
        );
        return ExitCode::ConfigError;
    }

    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

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

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org)
    );

    let body = serde_json::json!({
        "publisher_key": publisher_key,
        "role": role,
    });

    let payload = format!("org:invite:{org}:{publisher_key}:{role}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Invited {} to @{} as {}", publisher_key, org, role);
    ExitCode::Ok
}

fn cmd_org_remove(
    org: &str,
    publisher_key: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

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

    let url = format!(
        "{}/api/v1/orgs/{}/members/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org),
        urlencoding_simple(publisher_key)
    );

    let payload = format!("org:remove:{org}:{publisher_key}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .delete(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Removed {} from @{}", publisher_key, org);
    ExitCode::Ok
}

fn cmd_org_info(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

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

    let url = format!(
        "{}/api/v1/orgs/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
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
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let org_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("?");
    let display = resp_json
        .get("display_name")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let verified = resp_json
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let members = resp_json
        .get("member_count")
        .and_then(|m| m.as_i64())
        .unwrap_or(0);
    let packages = resp_json
        .get("package_count")
        .and_then(|p| p.as_i64())
        .unwrap_or(0);

    let _ = writeln!(stdout, "Organization: @{}", org_name);
    if !display.is_empty() {
        let _ = writeln!(stdout, "Display Name: {}", display);
    }
    let _ = writeln!(
        stdout,
        "Verified:     {}",
        if verified { "yes" } else { "no" }
    );
    let _ = writeln!(stdout, "Members:      {}", members);
    let _ = writeln!(stdout, "Packages:     {}", packages);

    ExitCode::Ok
}
