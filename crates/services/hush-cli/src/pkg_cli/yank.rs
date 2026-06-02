//! `pkg yank` — soft-delete a published package version from the registry.

use std::io::Write;

use super::auth::build_caller_auth_headers;
use super::util::urlencoding_simple;
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

pub(super) fn cmd_pkg_yank(
    name: &str,
    version: &str,
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

    let url = format!(
        "{}/api/v1/packages/{}/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
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

    let payload = format!("yank:{name}:{version}");
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
            let _ = writeln!(stderr, "Error: yank request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Yanked {} v{}", name, version);
    ExitCode::Ok
}
