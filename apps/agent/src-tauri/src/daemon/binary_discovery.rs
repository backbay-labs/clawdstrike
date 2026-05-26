//! Hushd binary discovery and managed-binary preparation.
//!
//! The agent prefers a writable managed copy of hushd under the user config
//! directory so OTA updates can be applied without needing the bundled
//! resource on disk to be writable. This module exposes:
//!
//! * `managed_hushd_path()` — canonical location for the writable binary.
//! * `prepare_managed_hushd_binary()` — seed the managed copy from the
//!   bundled resource (only on first run; OTA-applied updates persist).
//! * `find_hushd_binary()` — best-effort path resolution that consults the
//!   managed copy, bundled resources, `PATH`, and well-known install paths.

use anyhow::{Context, Result};
use std::path::PathBuf;

fn hushd_binary_name() -> &'static str {
    if cfg!(windows) {
        "hushd.exe"
    } else {
        "hushd"
    }
}

pub fn managed_hushd_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("bin")
        .join(hushd_binary_name())
}

fn bundled_hushd_candidates() -> Vec<PathBuf> {
    let binary = hushd_binary_name();
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Local dev/build target dir.
            candidates.push(exe_dir.join(binary));

            // macOS app bundle locations.
            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join(binary));
                candidates.push(contents_dir.join("Resources").join("bin").join(binary));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join(binary),
                );
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("bin")
                        .join(binary),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join(binary));
        candidates.push(root.join("resources").join("bin").join(binary));
        candidates.push(root.join("../../target/release").join(binary));
        candidates.push(root.join("../../target/debug").join(binary));
    }

    candidates
}

/// Ensure a writable managed hushd binary is available under user config.
///
/// Returns `Ok(Some(path))` when a bundled hushd was found and prepared,
/// `Ok(None)` when no bundled hushd candidate is present.
pub fn prepare_managed_hushd_binary() -> Result<Option<PathBuf>> {
    let Some(source_path) = bundled_hushd_candidates()
        .into_iter()
        .find(|candidate| candidate.is_file())
    else {
        return Ok(None);
    };

    let managed_path = managed_hushd_path();
    // Seed the managed binary once. Do not overwrite an existing managed binary
    // on startup, so OTA-applied updates remain persistent across app relaunches.
    let copy_needed = !managed_path.is_file();

    if copy_needed {
        if let Some(parent) = managed_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create managed hushd directory {:?}", parent)
            })?;
        }

        std::fs::copy(&source_path, &managed_path).with_context(|| {
            format!(
                "Failed to copy bundled hushd from {:?} to {:?}",
                source_path, managed_path
            )
        })?;
    } else {
        tracing::debug!(
            managed_path = %managed_path.display(),
            "Managed hushd already exists; preserving current binary"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&managed_path)
            .with_context(|| format!("Failed to stat managed hushd at {:?}", managed_path))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&managed_path, perms).with_context(|| {
            format!(
                "Failed to set executable permissions on managed hushd at {:?}",
                managed_path
            )
        })?;
    }

    #[cfg(target_os = "macos")]
    if copy_needed {
        let status = std::process::Command::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                managed_path.to_string_lossy().as_ref(),
            ])
            .status()
            .with_context(|| format!("Failed to invoke codesign for {:?}", managed_path))?;
        if !status.success() {
            anyhow::bail!(
                "codesign failed for managed hushd at {:?} with status {}",
                managed_path,
                status
            );
        }
    }

    Ok(Some(managed_path))
}

/// Find the hushd binary.
pub fn find_hushd_binary() -> Option<PathBuf> {
    let binary = hushd_binary_name();
    let mut candidates = vec![managed_hushd_path()];
    candidates.extend(bundled_hushd_candidates());
    candidates.extend(
        [
            which::which("hushd").ok(),
            Some(PathBuf::from("/usr/local/bin").join(binary)),
            Some(PathBuf::from("/opt/homebrew/bin").join(binary)),
            Some(PathBuf::from("/opt/clawdstrike/bin").join(binary)),
            dirs::home_dir().map(|p| p.join(".local/bin").join(binary)),
            dirs::home_dir().map(|p| p.join(".cargo/bin").join(binary)),
        ]
        .into_iter()
        .flatten(),
    );

    candidates.into_iter().find(|candidate| candidate.exists())
}
