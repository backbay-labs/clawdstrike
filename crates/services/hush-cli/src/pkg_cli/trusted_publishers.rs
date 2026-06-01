//! `pkg trusted-publishers` — manage OIDC trusted publishers for CI/CD
//! publishing (add, list, remove).

use std::io::Write;

use super::auth::{add_trusted_publisher_signed_payload, build_caller_auth_headers};
use super::util::urlencoding_simple;
use super::TrustedPublisherCommands;
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

pub(super) fn cmd_pkg_trusted_publishers(
    command: TrustedPublisherCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        TrustedPublisherCommands::Add {
            package,
            provider,
            repo,
            workflow,
            environment,
            registry,
        } => cmd_trusted_publisher_add(
            &package,
            &provider,
            &repo,
            workflow.as_deref(),
            environment.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        TrustedPublisherCommands::List { package, registry } => {
            cmd_trusted_publisher_list(&package, registry.as_deref(), stdout, stderr)
        }
        TrustedPublisherCommands::Remove {
            package,
            id,
            registry,
        } => cmd_trusted_publisher_remove(&package, id, registry.as_deref(), stdout, stderr),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_trusted_publisher_add(
    package: &str,
    provider: &str,
    repo: &str,
    workflow: Option<&str>,
    environment: Option<&str>,
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
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
    );

    let provider_norm = provider.to_ascii_lowercase();
    let mut body = serde_json::json!({
        "provider": provider_norm,
        "repository": repo,
    });
    if let Some(wf) = workflow {
        body["workflow"] = serde_json::Value::String(wf.to_string());
    }
    if let Some(env) = environment {
        body["environment"] = serde_json::Value::String(env.to_string());
    }

    let payload =
        add_trusted_publisher_signed_payload(package, &provider_norm, repo, workflow, environment);
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

    let _ = writeln!(
        stdout,
        "Added trusted publisher for {}: {} ({})",
        package, repo, provider
    );
    ExitCode::Ok
}

fn cmd_trusted_publisher_list(
    package: &str,
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
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
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

    let publishers = resp_json
        .get("trusted_publishers")
        .and_then(|v| v.as_array());

    match publishers {
        Some(list) if !list.is_empty() => {
            let _ = writeln!(stdout, "Trusted publishers for {}:", package);
            for tp in list {
                let id = tp.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                let provider = tp.get("provider").and_then(|v| v.as_str()).unwrap_or("?");
                let repository = tp.get("repository").and_then(|v| v.as_str()).unwrap_or("?");
                let workflow = tp.get("workflow").and_then(|v| v.as_str()).unwrap_or("-");
                let environment = tp
                    .get("environment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let _ = writeln!(
                    stdout,
                    "  [{}] {} {} (workflow: {}, env: {})",
                    id, provider, repository, workflow, environment
                );
            }
        }
        _ => {
            let _ = writeln!(stdout, "No trusted publishers configured for {}.", package);
        }
    }

    ExitCode::Ok
}

fn cmd_trusted_publisher_remove(
    package: &str,
    id: i64,
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
        "{}/api/v1/packages/{}/trusted-publishers/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package),
        id
    );

    let payload = format!("trusted-publisher:remove:{package}:{id}");
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

    let _ = writeln!(stdout, "Removed trusted publisher {} from {}", id, package);
    ExitCode::Ok
}
