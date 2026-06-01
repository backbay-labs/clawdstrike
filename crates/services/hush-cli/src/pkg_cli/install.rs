//! `pkg install` — install a package from a local `.cpkg` file or the
//! registry, with download-size limits, identity checks, trust verification,
//! and rollback on failure.

use std::io::{Read as IoRead, Write};
use std::path::{Path, PathBuf};

use clawdstrike::pkg::archive;
use clawdstrike::pkg::manifest::parse_pkg_manifest_toml;
use clawdstrike::pkg::store::{compute_content_fingerprint, PackageStore};

use super::trust::{verify_install_trust, InstalledIdentity};
use super::util::{tempdir_for_download, urlencoding_simple};
use super::MAX_REGISTRY_DOWNLOAD_BYTES;
use crate::registry_config::{is_file_source, RegistryConfig};
use crate::ExitCode;

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

pub(super) fn select_default_registry_version(info: &serde_json::Value) -> Option<String> {
    let versions = info.get("versions").and_then(|v| v.as_array());
    let latest_hint = info.get("latest_version").and_then(|v| v.as_str());

    if let Some(latest) = latest_hint {
        let hint_allowed = versions.is_none_or(|arr| {
            arr.iter().any(|entry| {
                entry.get("version").and_then(|v| v.as_str()) == Some(latest)
                    && matches!(entry.get("yanked").and_then(|v| v.as_bool()), Some(false))
            })
        });
        if hint_allowed {
            return Some(latest.to_string());
        }
    }

    if let Some(arr) = versions {
        let mut best: Option<(String, Option<chrono::DateTime<chrono::FixedOffset>>, usize)> = None;
        for (idx, entry) in arr.iter().enumerate() {
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let yanked = match entry.get("yanked").and_then(|v| v.as_bool()) {
                Some(flag) => flag,
                None => continue,
            };
            if yanked {
                continue;
            }
            let published_at = entry
                .get("published_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());

            let replace = match &best {
                None => true,
                Some((_, best_ts, best_idx)) => match (published_at, *best_ts) {
                    (Some(current), Some(existing)) => {
                        current > existing || (current == existing && idx > *best_idx)
                    }
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => idx > *best_idx,
                },
            };
            if replace {
                best = Some((version.to_string(), published_at, idx));
            }
        }
        if let Some((version, _, _)) = best {
            return Some(version);
        }
        return None;
    }

    latest_hint.map(ToOwned::to_owned)
}

pub(super) fn recompute_installed_content_fingerprint(
    package_dir: &Path,
) -> Result<hush_core::Hash, String> {
    compute_content_fingerprint(package_dir)
        .map_err(|e| format!("failed to recompute installed package fingerprint: {e}"))
}

fn read_response_bytes_limited(
    mut response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|len| len > max_bytes) {
        return Err(format!(
            "download exceeds max allowed size ({} bytes)",
            max_bytes
        ));
    }

    let mut bytes = Vec::new();
    let mut limited = response.by_ref().take(max_bytes + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read response: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "download exceeds max allowed size ({} bytes)",
            max_bytes
        ));
    }
    Ok(bytes)
}

fn cmd_pkg_install_registry(
    name: &str,
    version: Option<&str>,
    registry: Option<&str>,
    trust_level: &str,
    allow_unverified: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // When version is omitted, resolve the latest version from the registry.
    let resolved_version: String;
    let version_segment: &str = match version {
        Some(v) => v,
        None => {
            let info_url = format!(
                "{}/api/v1/packages/{}",
                cfg.registry_url.trim_end_matches('/'),
                urlencoding_simple(name)
            );
            let info_resp = match client.get(&info_url).send() {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(
                        stderr,
                        "Error: cannot fetch package metadata to resolve install version: {e}"
                    );
                    return ExitCode::RuntimeError;
                }
            };
            if !info_resp.status().is_success() {
                let status = info_resp.status();
                let _ = writeln!(
                    stderr,
                    "Error: cannot resolve default install version (HTTP {status}). \
                     Specify --version explicitly."
                );
                return ExitCode::RuntimeError;
            }
            let info: serde_json::Value = match info_resp.json() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: invalid package info response: {e}");
                    return ExitCode::RuntimeError;
                }
            };
            // Prefer the newest non-yanked version from package metadata.
            let latest = select_default_registry_version(&info);
            match latest {
                Some(v) => {
                    resolved_version = v;
                    &resolved_version
                }
                None => {
                    let _ = writeln!(
                        stderr,
                        "Error: cannot determine installable version for '{name}'. \
                         All available versions may be yanked; specify --version explicitly."
                    );
                    return ExitCode::RuntimeError;
                }
            }
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/{}/download",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version_segment)
    );

    let _ = writeln!(stdout, "Downloading {} v{} ...", name, version_segment);

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: download failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let bytes = match read_response_bytes_limited(resp, MAX_REGISTRY_DOWNLOAD_BYTES) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Write to a temp file, then install
    let tmp_dir = match tempdir_for_download() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create temp dir: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let cpkg_path = tmp_dir.join(format!(
        "{}-{}.cpkg",
        name.replace('/', "-").replace('@', ""),
        version_segment
    ));
    if let Err(e) = std::fs::write(&cpkg_path, &bytes) {
        let _ = writeln!(stderr, "Error: cannot write temp file: {e}");
        return ExitCode::RuntimeError;
    }

    let (archive_name, archive_version) = match read_archive_identity(&cpkg_path) {
        Ok(identity) => identity,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };
    if archive_name != name || archive_version != version_segment {
        let _ = writeln!(
            stderr,
            "Error: downloaded package identity mismatch (requested {}@{}, archive {}@{}). \
             Installation aborted before modifying local installs.",
            name, version_segment, archive_name, archive_version
        );
        return ExitCode::Fail;
    }

    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let existing_install = match store.get(name, version_segment) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot check existing install state: {e}");
            return ExitCode::RuntimeError;
        }
    };
    let mut rollback_backup = match create_install_rollback_backup(existing_install.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let installed = match store.install_from_file(&cpkg_path) {
        Ok(p) => p,
        Err(e) => {
            cleanup_install_backup(rollback_backup.take());
            let _ = writeln!(stderr, "Error: install failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !requested_identity_matches_install(name, version_segment, &installed) {
        if let Err(e) = store.remove(&installed.name, &installed.version) {
            let backup_hint = rollback_backup.as_ref().map_or(String::new(), |backup| {
                format!(
                    " Rollback backup retained at {}.",
                    backup.backup_path.display()
                )
            });
            let _ = writeln!(
                stderr,
                "Error: failed to roll back mismatched install removal ({}@{}): {}.{}",
                installed.name, installed.version, e, backup_hint
            );
            return ExitCode::RuntimeError;
        }
        if let Some(backup) = rollback_backup.take() {
            if let Err(e) = restore_install_from_backup(&backup) {
                let _ = writeln!(stderr, "Error: failed to restore previous install: {e}");
                return ExitCode::RuntimeError;
            }
        }
        let _ = writeln!(
            stderr,
            "Error: downloaded package identity mismatch (requested {}@{}, installed {}@{})",
            name, version_segment, installed.name, installed.version
        );
        return ExitCode::Fail;
    }

    // Cleanup temp
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Trust verification for registry installs.
    if !allow_unverified && trust_level != "unverified" {
        let trust_ok = verify_install_trust(
            InstalledIdentity {
                name: &installed.name,
                version: &installed.version,
                content_hash: &installed.content_hash,
            },
            &cfg,
            &client,
            trust_level,
            stdout,
            stderr,
        );
        if !trust_ok {
            // Remove the installed package since trust verification failed.
            if let Err(e) = store.remove(&installed.name, &installed.version) {
                let backup_hint = rollback_backup.as_ref().map_or(String::new(), |backup| {
                    format!(
                        " Rollback backup retained at {}.",
                        backup.backup_path.display()
                    )
                });
                let _ = writeln!(
                    stderr,
                    "Error: trust verification failed and package rollback removal failed ({}@{}): {}.{}",
                    installed.name, installed.version, e, backup_hint
                );
                return ExitCode::RuntimeError;
            }
            let mut restored_previous = false;
            if let Some(backup) = rollback_backup.take() {
                if let Err(e) = restore_install_from_backup(&backup) {
                    let _ = writeln!(stderr, "Error: failed to restore previous install: {e}");
                    return ExitCode::RuntimeError;
                }
                restored_previous = true;
            }
            if restored_previous {
                let _ = writeln!(
                    stderr,
                    "Error: trust verification failed. Existing install was restored. \
                     Use --allow-unverified to skip trust checks."
                );
            } else {
                let _ = writeln!(
                    stderr,
                    "Error: package removed because trust verification failed. \
                     Use --allow-unverified to skip trust checks."
                );
            }
            return ExitCode::Fail;
        }
    }

    cleanup_install_backup(rollback_backup.take());

    let _ = writeln!(
        stdout,
        "Installed: {} v{}",
        installed.name, installed.version
    );
    let _ = writeln!(stdout, "Path:      {}", installed.path.display());
    let _ = writeln!(stdout, "Hash:      {}", installed.content_hash.to_hex());
    ExitCode::Ok
}
