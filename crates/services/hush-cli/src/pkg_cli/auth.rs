//! Caller-authentication header construction shared by registry-mutating
//! subcommands (publish, yank, org, trusted-publishers).

use std::io::Write;

use crate::registry_config::{load_or_generate_publisher_keypair, RegistryConfig};
use crate::ExitCode;

pub(super) struct CallerAuthHeaders {
    pub(super) key_hex: String,
    pub(super) sig_hex: String,
    pub(super) ts: String,
}

fn encode_signed_field(value: &str) -> String {
    format!("{}:{value}", value.len())
}

pub(super) fn add_trusted_publisher_signed_payload(
    package_name: &str,
    provider: &str,
    repository: &str,
    workflow: Option<&str>,
    environment: Option<&str>,
) -> String {
    format!(
        "trusted-publisher:add:v2:name={};provider={};repository={};workflow={};environment={}",
        encode_signed_field(package_name),
        encode_signed_field(provider),
        encode_signed_field(repository),
        encode_signed_field(workflow.unwrap_or("")),
        encode_signed_field(environment.unwrap_or("")),
    )
}

pub(super) fn build_caller_auth_headers(
    cfg: &RegistryConfig,
    payload: &str,
    stderr: &mut dyn Write,
) -> Result<CallerAuthHeaders, ExitCode> {
    let keypair = load_or_generate_publisher_keypair(cfg, stderr).map_err(|e| {
        let _ = writeln!(stderr, "Error: {e}");
        ExitCode::RuntimeError
    })?;
    let ts = chrono::Utc::now().to_rfc3339();
    let msg = format!("clawdstrike-registry-auth:v1:{payload}:{ts}");
    let sig = keypair.sign(msg.as_bytes()).to_hex();
    Ok(CallerAuthHeaders {
        key_hex: keypair.public_key().to_hex(),
        sig_hex: sig,
        ts,
    })
}
