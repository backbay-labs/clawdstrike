//! Local API auth token management.

use crate::settings::get_agent_token_path;
use anyhow::{Context, Result};
use std::fs;

/// Ensure the local API auth token exists and return it.
pub fn ensure_local_api_token() -> Result<String> {
    let path = get_agent_token_path();

    if path.exists() {
        let token = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read local API token from {:?}", path))?
            .trim()
            .to_string();

        if !token.is_empty() {
            return Ok(token);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create auth token directory {:?}", parent))?;
    }

    let token = format!("clawdstrike-{}", uuid::Uuid::new_v4());
    fs::write(&path, format!("{}\n", token))
        .with_context(|| format!("Failed to write local API token to {:?}", path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .with_context(|| format!("Failed to stat local API token file {:?}", path))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)
            .with_context(|| format!("Failed to set local API token permissions on {:?}", path))?;
    }

    Ok(token)
}
