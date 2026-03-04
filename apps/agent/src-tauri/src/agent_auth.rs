//! Local API auth token management.

use crate::settings::get_agent_token_path;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Write;

/// Read the currently persisted local API auth token without creating/rotating it.
pub fn read_local_api_token() -> Result<String> {
    let path = get_agent_token_path();
    read_token_file(&path)
}

/// Ensure the local API auth token exists and return it.
pub fn ensure_local_api_token() -> Result<String> {
    let path = get_agent_token_path();

    if path.exists() {
        match read_token_file(&path) {
            Ok(token) => return Ok(token),
            Err(err) => tracing::warn!(error = %err, "Existing local API token file is invalid"),
        };
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create auth token directory {:?}", parent))?;
    }

    let token = generate_local_api_token();
    write_token_file(&path, &token)?;
    enforce_token_permissions(&path)?;

    Ok(token)
}

fn read_token_file(path: &std::path::Path) -> Result<String> {
    enforce_token_permissions(path)?;
    let token = fs::read_to_string(path)
        .with_context(|| format!("Failed to read local API token from {:?}", path))?
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(anyhow!("Local API token file {:?} is empty", path));
    }
    Ok(token)
}

/// Rotate the local API auth token and persist it.
pub fn rotate_local_api_token() -> Result<String> {
    let path = get_agent_token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create auth token directory {:?}", parent))?;
    }

    let token = generate_local_api_token();
    write_token_file(&path, &token)?;
    enforce_token_permissions(&path)?;
    Ok(token)
}

fn generate_local_api_token() -> String {
    format!("clawdstrike-{}", uuid::Uuid::new_v4())
}

fn write_token_file(path: &std::path::Path, token: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to open local API token file {:?}", path))?;
        file.write_all(format!("{token}\n").as_bytes())
            .with_context(|| format!("Failed to write local API token to {:?}", path))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync local API token file {:?}", path))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, format!("{token}\n"))
            .with_context(|| format!("Failed to write local API token to {:?}", path))?;
        Ok(())
    }
}

fn enforce_token_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("Failed to stat local API token file {:?}", path))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to set local API token permissions on {:?}", path))?;
    }

    Ok(())
}
