//! Filesystem helpers used across the settings module.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

pub fn get_settings_path() -> PathBuf {
    get_config_dir().join("agent.json")
}

pub fn get_agent_token_path() -> PathBuf {
    get_config_dir().join("agent-local-token")
}

pub fn hostname_best_effort() -> String {
    hostname::get()
        .ok()
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn ensure_default_policy(bundled_policy: &str) -> Result<PathBuf> {
    let policy_path = super::defaults::default_policy_path();

    if !policy_path.exists() {
        if let Some(parent) = policy_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        std::fs::write(&policy_path, bundled_policy)
            .with_context(|| format!("Failed to write default policy to {:?}", policy_path))?;

        tracing::info!(path = ?policy_path, "Created default policy");
    }

    Ok(policy_path)
}

#[cfg(unix)]
pub(crate) fn enforce_private_mode(path: &std::path::Path, target: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read {target} metadata {:?}", path))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set {target} permissions on {:?}", path))?;
    }
    Ok(())
}

pub(super) fn write_settings_file(path: &std::path::Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create settings file {:?}", path))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("Failed to write settings to {:?}", path))?;
        enforce_private_mode(path, "settings file")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write settings to {:?}", path))?;
    }

    Ok(())
}
