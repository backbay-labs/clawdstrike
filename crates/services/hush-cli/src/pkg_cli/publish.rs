//! `pkg login` and `pkg publish` — publisher authentication and package
//! publication (including OIDC token acquisition for CI/CD).

use std::io::Write;
use std::path::Path;

use clawdstrike::pkg::integrity::sign_package;
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgManifest};

use super::pack::{archive_file_name, pack_source_dir_without_embedded_archives};
use crate::registry_config::{load_or_generate_publisher_keypair, RegistryConfig};
use crate::ExitCode;

pub(super) fn cmd_pkg_login(
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    // Load or generate publisher keypair locally.
    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let public_key_hex = keypair.public_key().to_hex();

    // If an auth token is already configured (via env var or credentials file),
    // report success immediately.
    if cfg.auth_token.is_some() {
        let _ = writeln!(stdout, "Already authenticated.");
        let _ = writeln!(stdout, "Publisher key: {public_key_hex}");
        let _ = writeln!(stdout, "Registry: {}", cfg.registry_url);
        return ExitCode::Ok;
    }

    // Store the keypair locally. The auth token can be set via
    // CLAWDSTRIKE_AUTH_TOKEN env var or written to
    // ~/.clawdstrike/credentials.toml manually.
    //
    // TODO: A `/api/v1/auth/register` endpoint will be added in a future phase
    // to enable automated token exchange. For now, register your public key with
    // the registry administrator and set the token manually.
    let _ = writeln!(stdout, "Publisher keypair ready.");
    let _ = writeln!(stdout, "Publisher key: {public_key_hex}");
    let _ = writeln!(stdout, "Registry: {}", cfg.registry_url);
    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "To complete login, set your auth token via one of:");
    let _ = writeln!(stdout, "  export CLAWDSTRIKE_AUTH_TOKEN=<your-token>");
    let _ = writeln!(
        stdout,
        "  echo '[registry]\\nauth_token = \"<your-token>\"' > ~/.clawdstrike/credentials.toml"
    );
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg publish
// ---------------------------------------------------------------------------

pub(super) fn cmd_pkg_publish(
    path: Option<&Path>,
    registry: Option<&str>,
    oidc: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let source_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    let cfg = RegistryConfig::load(registry);

    // For OIDC publishing, obtain the identity token from CI/CD environment.
    let auth_token = if oidc {
        match obtain_oidc_token(stderr) {
            Ok(t) => t,
            Err(code) => return code,
        }
    } else {
        match &cfg.auth_token {
            Some(t) => t.clone(),
            None => {
                let _ = writeln!(
                    stderr,
                    "Error: not authenticated. Run `clawdstrike pkg login` first."
                );
                return ExitCode::ConfigError;
            }
        }
    };

    // Read and validate manifest
    let manifest_path = source_dir.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read clawdstrike-pkg.toml: {e}");
            return ExitCode::ConfigError;
        }
    };

    let manifest: PkgManifest = match parse_pkg_manifest_toml(&manifest_str) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid manifest: {e}");
            return ExitCode::ConfigError;
        }
    };

    let pkg_name = &manifest.package.name;
    let pkg_version = &manifest.package.version;

    // Pack the archive
    let archive_name = archive_file_name(pkg_name, pkg_version);
    let output_path = source_dir.join(&archive_name);

    let _ = writeln!(stdout, "Packing {} v{} ...", pkg_name, pkg_version);

    if let Err(e) = pack_source_dir_without_embedded_archives(&source_dir, &output_path) {
        let _ = writeln!(stderr, "Error: {e}");
        return ExitCode::RuntimeError;
    }

    // Sign the archive
    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let signature = match sign_package(&output_path, &keypair) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: signing failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Upload
    let url = format!("{}/api/v1/packages", cfg.registry_url.trim_end_matches('/'));

    let cpkg_bytes = match std::fs::read(&output_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read archive: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    use base64::Engine as _;
    let publish_body = serde_json::json!({
        "archive_base64": base64::engine::general_purpose::STANDARD.encode(&cpkg_bytes),
        "publisher_key": keypair.public_key().to_hex(),
        "publisher_sig": signature.signature.to_hex(),
        "manifest_toml": manifest_str,
    });

    let mut request_builder = client.post(&url).bearer_auth(&auth_token);

    if oidc {
        request_builder = request_builder.header("X-Clawdstrike-Auth-Type", "oidc");
        // Detect provider from env vars.
        let provider = if std::env::var("GITHUB_ACTIONS").is_ok() {
            "github"
        } else if std::env::var("GITLAB_CI").is_ok() {
            "gitlab"
        } else {
            "github"
        };
        request_builder = request_builder.header("X-Clawdstrike-Oidc-Provider", provider);
    }

    let resp = match request_builder.json(&publish_body).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: publish request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Published {} v{}", pkg_name, pkg_version);
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// OIDC token acquisition
// ---------------------------------------------------------------------------

/// Obtain an OIDC identity token from the CI/CD environment.
///
/// GitHub Actions: uses `ACTIONS_ID_TOKEN_REQUEST_TOKEN` + `ACTIONS_ID_TOKEN_REQUEST_URL`.
/// GitLab CI: uses `CI_JOB_JWT_V2`.
fn obtain_oidc_token(stderr: &mut dyn Write) -> Result<String, ExitCode> {
    // GitLab CI: direct JWT env var.
    if let Ok(jwt) = std::env::var("CI_JOB_JWT_V2") {
        if !jwt.is_empty() {
            return Ok(jwt);
        }
    }

    // GitHub Actions: request a token from the OIDC provider.
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();

    if let (Some(token), Some(url)) = (request_token, request_url) {
        if !token.is_empty() && !url.is_empty() {
            let url_with_audience = format!("{url}&audience=clawdstrike-registry");
            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            let resp = match client.get(&url_with_audience).bearer_auth(&token).send() {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: failed to request OIDC token: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let _ = writeln!(stderr, "Error: OIDC token request returned HTTP {status}");
                return Err(ExitCode::RuntimeError);
            }

            let body: serde_json::Value = match resp.json() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: invalid OIDC token response: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            if let Some(value) = body.get("value").and_then(|v| v.as_str()) {
                return Ok(value.to_string());
            }

            let _ = writeln!(stderr, "Error: OIDC token response missing 'value' field");
            return Err(ExitCode::RuntimeError);
        }
    }

    let _ = writeln!(
        stderr,
        "Error: --oidc requires a CI/CD environment (GitHub Actions or GitLab CI)"
    );
    Err(ExitCode::ConfigError)
}
