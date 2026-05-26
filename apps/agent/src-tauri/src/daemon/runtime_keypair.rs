//! Runtime keypair materialization for hushd.
//!
//! The agent generates a per-daemon-port signing keypair for hushd and (when
//! an enrollment identity is provisioned) materializes the runtime enrollment
//! keypair into the runtime config directory so hushd can sign Spine events.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) fn runtime_enrollment_keypair_path(runtime_parent: &Path, daemon_port: u16) -> PathBuf {
    runtime_parent.join(format!("agent.runtime.{}.key", daemon_port))
}

pub(super) fn runtime_signing_keypair_path(runtime_parent: &Path, daemon_port: u16) -> PathBuf {
    runtime_parent.join(format!("hushd.signing.{}.key", daemon_port))
}

pub(super) fn materialize_runtime_signing_keypair(
    runtime_parent: &Path,
    daemon_port: u16,
) -> Result<PathBuf> {
    let key_path = runtime_signing_keypair_path(runtime_parent, daemon_port);
    if key_path.exists() {
        return Ok(key_path);
    }

    let keypair = hush_core::Keypair::generate();
    let normalized = format!("{}\n", keypair.to_hex());
    crate::security::fs::write_private_atomic(
        &key_path,
        normalized.as_bytes(),
        "runtime hushd signing keypair",
    )?;
    Ok(key_path)
}

pub(super) fn materialize_runtime_enrollment_keypair(
    runtime_parent: &Path,
    daemon_port: u16,
) -> Result<Option<PathBuf>> {
    let key_hex = match crate::enrollment::load_enrollment_key_hex()
        .with_context(|| "Failed to load enrollment key for runtime config")?
    {
        Some(value) => value,
        None => return Ok(None),
    };

    let key_path = runtime_enrollment_keypair_path(runtime_parent, daemon_port);
    let normalized = format!("{}\n", key_hex.trim());
    crate::security::fs::write_private_atomic(
        &key_path,
        normalized.as_bytes(),
        "runtime enrollment keypair",
    )?;
    Ok(Some(key_path))
}

pub(super) fn cleanup_runtime_enrollment_keypair(daemon_port: u16) -> Result<()> {
    let runtime_parent = crate::settings::get_config_dir().join("runtime");
    let key_path = runtime_enrollment_keypair_path(&runtime_parent, daemon_port);
    if key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("Failed to remove runtime enrollment key {:?}", key_path))?;
    }
    Ok(())
}
