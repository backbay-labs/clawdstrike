//! `pkg install` — install a package from a local `.cpkg` file or the
//! registry, with download-size limits, identity checks, trust verification,
//! and rollback on failure.

use std::io::Write;
use std::path::{Path, PathBuf};

use clawdstrike::pkg::archive;
use clawdstrike::pkg::manifest::parse_pkg_manifest_toml;
use clawdstrike::pkg::store::{compute_content_fingerprint, PackageStore};

use crate::registry_config::is_file_source;
use crate::ExitCode;

mod registry;

use registry::cmd_pkg_install_registry;
#[cfg(test)]
pub(super) use registry::select_default_registry_version;

pub(super) fn cmd_pkg_install(
    source: &str,
    version: Option<&str>,
    registry: Option<&str>,
    trust_level: Option<&str>,
    allow_unverified: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    // Validate trust level if provided.
    let level = trust_level.unwrap_or("signed");
    if !matches!(level, "unverified" | "signed" | "verified" | "certified") {
        let _ = writeln!(
            stderr,
            "Error: invalid trust level '{}'. Must be one of: unverified, signed, verified, certified",
            level
        );
        return ExitCode::ConfigError;
    }

    if is_file_source(source) {
        return cmd_pkg_install_local(Path::new(source), allow_unverified, stdout, stderr);
    }

    if level == "unverified" && !allow_unverified {
        let _ = writeln!(
            stderr,
            "Error: trust level 'unverified' requires --allow-unverified flag"
        );
        return ExitCode::ConfigError;
    }

    if allow_unverified {
        let _ = writeln!(
            stderr,
            "Warning: installing without trust verification. Use at your own risk."
        );
    }

    cmd_pkg_install_registry(
        source,
        version,
        registry,
        level,
        allow_unverified,
        stdout,
        stderr,
    )
}

fn cmd_pkg_install_local(
    source: &Path,
    allow_unverified: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if !source.exists() {
        let _ = writeln!(stderr, "Error: file not found: {}", source.display());
        return ExitCode::ConfigError;
    }
    if !allow_unverified {
        let _ = writeln!(
            stderr,
            "Error: local .cpkg installs are unverified and require --allow-unverified. \
             Install by package name from a configured registry to enforce signed/verified/certified trust."
        );
        return ExitCode::ConfigError;
    }
    let _ = writeln!(
        stderr,
        "Warning: installing local .cpkg without registry trust verification."
    );

    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let installed = match store.install_from_file(source) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: install failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(
        stdout,
        "Installed: {} v{}",
        installed.name, installed.version
    );
    let _ = writeln!(stdout, "Path:      {}", installed.path.display());
    let _ = writeln!(stdout, "Hash:      {}", installed.content_hash.to_hex());
    ExitCode::Ok
}

pub(super) fn requested_identity_matches_install(
    requested_name: &str,
    requested_version: &str,
    installed: &clawdstrike::pkg::store::InstalledPackage,
) -> bool {
    installed.name == requested_name && installed.version == requested_version
}

pub(super) fn read_archive_identity(cpkg_path: &Path) -> Result<(String, String), String> {
    let nonce: u64 = rand::Rng::random(&mut rand::rng());
    let scratch = std::env::temp_dir().join(format!("clawdstrike_identity_{nonce:x}"));
    std::fs::create_dir_all(&scratch).map_err(|e| {
        format!("cannot create temporary directory to inspect downloaded package: {e}")
    })?;

    let result = (|| {
        let unpack_dir = scratch.join("unpacked");
        archive::unpack(cpkg_path, &unpack_dir)
            .map_err(|e| format!("downloaded package is not a valid .cpkg archive: {e}"))?;
        let manifest_path = unpack_dir.join("clawdstrike-pkg.toml");
        let manifest_str = std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("downloaded archive missing clawdstrike-pkg.toml: {e}"))?;
        let manifest = parse_pkg_manifest_toml(&manifest_str)
            .map_err(|e| format!("downloaded archive manifest is invalid: {e}"))?;
        Ok((manifest.package.name, manifest.package.version))
    })();

    let _ = std::fs::remove_dir_all(&scratch);
    result
}

#[derive(Debug)]
pub(super) struct InstallRollbackBackup {
    original_path: PathBuf,
    pub(super) backup_path: PathBuf,
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub(super) fn create_install_rollback_backup(
    existing: Option<&clawdstrike::pkg::store::InstalledPackage>,
) -> Result<Option<InstallRollbackBackup>, String> {
    let Some(existing) = existing else {
        return Ok(None);
    };

    let nonce: u64 = rand::Rng::random(&mut rand::rng());
    let backup_path = existing
        .path
        .with_extension(format!("pretrust.bak.{nonce:x}"));
    if backup_path.exists() {
        std::fs::remove_dir_all(&backup_path).map_err(|e| {
            format!(
                "failed to clear stale rollback backup {}: {e}",
                backup_path.display()
            )
        })?;
    }
    copy_dir_recursive(&existing.path, &backup_path).map_err(|e| {
        format!(
            "failed to create rollback backup for {}: {e}",
            existing.path.display()
        )
    })?;
    Ok(Some(InstallRollbackBackup {
        original_path: existing.path.clone(),
        backup_path,
    }))
}

pub(super) fn restore_install_from_backup(backup: &InstallRollbackBackup) -> Result<(), String> {
    if !backup.backup_path.exists() {
        return Err(format!(
            "rollback backup not found at {}",
            backup.backup_path.display()
        ));
    }
    if backup.original_path.exists() {
        std::fs::remove_dir_all(&backup.original_path).map_err(|e| {
            format!(
                "failed to remove failed install at {}: {e}",
                backup.original_path.display()
            )
        })?;
    }
    if let Some(parent) = backup.original_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create install parent directory {}: {e}",
                parent.display()
            )
        })?;
    }
    match std::fs::rename(&backup.backup_path, &backup.original_path) {
        Ok(()) => Ok(()),
        Err(_) => {
            copy_dir_recursive(&backup.backup_path, &backup.original_path).map_err(|e| {
                format!(
                    "failed to restore install from backup {}: {e}",
                    backup.backup_path.display()
                )
            })?;
            std::fs::remove_dir_all(&backup.backup_path).map_err(|e| {
                format!(
                    "failed to clean rollback backup {}: {e}",
                    backup.backup_path.display()
                )
            })?;
            Ok(())
        }
    }
}

fn cleanup_install_backup(backup: Option<InstallRollbackBackup>) {
    if let Some(backup) = backup {
        let _ = std::fs::remove_dir_all(&backup.backup_path);
    }
}

pub(super) fn recompute_installed_content_fingerprint(
    package_dir: &Path,
) -> Result<hush_core::Hash, String> {
    compute_content_fingerprint(package_dir)
        .map_err(|e| format!("failed to recompute installed package fingerprint: {e}"))
}
