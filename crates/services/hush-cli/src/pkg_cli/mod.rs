#![allow(clippy::needless_pass_by_value)]
//! `hush pkg` subcommands — package management for `.cpkg` archives.

use std::io::{Read as IoRead, Write};
use std::path::{Path, PathBuf};

use hush_core::Hash;

use clawdstrike::pkg::archive;
use clawdstrike::pkg::integrity::sign_package;
#[cfg(test)]
use clawdstrike::pkg::manifest::PkgType;
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgManifest};
#[cfg(test)]
use clawdstrike::pkg::merkle::LeafData;
use clawdstrike::pkg::store::{compute_content_fingerprint, PackageStore, StoreMetadata};

use crate::registry_config::{is_file_source, load_or_generate_publisher_keypair, RegistryConfig};
use crate::ExitCode;

pub(super) const PLUGIN_MANIFEST_FILENAME: &str = "clawdstrike.plugin.toml";
const MAX_REGISTRY_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;

mod auth;
mod command;
mod init;
mod pack;
mod scaffold;
mod search;
mod trust;
mod util;
mod yank;

use auth::{add_trusted_publisher_signed_payload, build_caller_auth_headers};
pub use command::{CliPkgType, OrgCommands, PkgCommands, TrustedPublisherCommands};
use init::cmd_pkg_init;
#[cfg(test)]
use pack::validate_pack_contents;
use pack::{archive_file_name, cmd_pkg_pack, pack_source_dir_without_embedded_archives};
#[cfg(feature = "wasm-plugin-runtime")]
use scaffold::sanitize_cargo_package_name;
#[cfg(test)]
use scaffold::scaffold_package;
use search::cmd_pkg_search;
#[cfg(test)]
use trust::checkpoint_signature_message;
use trust::{
    required_registry_public_key_for_trust, verify_attestation_against_hash, verify_install_trust,
    verify_transparency_proof, InstalledIdentity, RegistryAttestation, RegistryProof,
};
#[cfg(test)]
use util::truncate_with_ellipsis;
use util::{format_number, tempdir_for_download, urlencoding_simple};
use yank::cmd_pkg_yank;

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub fn cmd_pkg(command: PkgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        PkgCommands::Init { pkg_type, name } => cmd_pkg_init(&pkg_type, &name, stdout, stderr),
        PkgCommands::Pack { path } => cmd_pkg_pack(path.as_deref(), stdout, stderr),
        PkgCommands::Install {
            source,
            version,
            registry,
            trust_level,
            allow_unverified,
        } => cmd_pkg_install(
            &source,
            version.as_deref(),
            registry.as_deref(),
            trust_level.as_deref(),
            allow_unverified,
            stdout,
            stderr,
        ),
        PkgCommands::List => cmd_pkg_list(stdout, stderr),
        PkgCommands::Verify {
            name,
            version,
            trust_level,
            registry,
        } => cmd_pkg_verify(
            &name,
            &version,
            &trust_level,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        PkgCommands::Info { name, version } => cmd_pkg_info(&name, &version, stdout, stderr),
        PkgCommands::Test { path, filter } => {
            cmd_pkg_test(path.as_deref(), filter.as_deref(), stdout, stderr)
        }
        PkgCommands::Login { registry } => cmd_pkg_login(registry.as_deref(), stdout, stderr),
        PkgCommands::Publish {
            path,
            registry,
            oidc,
        } => cmd_pkg_publish(path.as_deref(), registry.as_deref(), oidc, stdout, stderr),
        PkgCommands::Search {
            query,
            limit,
            page,
            registry,
        } => cmd_pkg_search(&query, limit, page, registry.as_deref(), stdout, stderr),
        PkgCommands::Audit {
            name,
            registry,
            limit,
        } => cmd_pkg_audit(&name, registry.as_deref(), limit, stdout, stderr),
        PkgCommands::Yank {
            name,
            version,
            registry,
        } => cmd_pkg_yank(&name, &version, registry.as_deref(), stdout, stderr),
        PkgCommands::Stats { name, registry } => {
            cmd_pkg_stats(&name, registry.as_deref(), stdout, stderr)
        }
        PkgCommands::TrustedPublishers { command } => {
            cmd_pkg_trusted_publishers(command, stdout, stderr)
        }
        PkgCommands::Org { command } => cmd_pkg_org(command, stdout, stderr),
        PkgCommands::Mirror { command } => crate::mirror::cmd_mirror(command, stdout, stderr),
    }
}

// ---------------------------------------------------------------------------
// pkg install
// ---------------------------------------------------------------------------

fn cmd_pkg_install(
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

fn requested_identity_matches_install(
    requested_name: &str,
    requested_version: &str,
    installed: &clawdstrike::pkg::store::InstalledPackage,
) -> bool {
    installed.name == requested_name && installed.version == requested_version
}

fn read_archive_identity(cpkg_path: &Path) -> Result<(String, String), String> {
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
struct InstallRollbackBackup {
    original_path: PathBuf,
    backup_path: PathBuf,
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

fn create_install_rollback_backup(
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

fn restore_install_from_backup(backup: &InstallRollbackBackup) -> Result<(), String> {
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

fn select_default_registry_version(info: &serde_json::Value) -> Option<String> {
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

fn recompute_installed_content_fingerprint(package_dir: &Path) -> Result<hush_core::Hash, String> {
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

// ---------------------------------------------------------------------------
// pkg list
// ---------------------------------------------------------------------------

fn cmd_pkg_list(stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let packages = match store.list() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot list packages: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if packages.is_empty() {
        let _ = writeln!(stdout, "No packages installed.");
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "{:<40} {:<12} HASH", "NAME", "VERSION");
    let _ = writeln!(stdout, "{}", "-".repeat(72));
    for pkg in &packages {
        let hash_hex = pkg.content_hash.to_hex();
        let hash_display = if hash_hex.len() > 16 {
            &hash_hex[..16]
        } else {
            &hash_hex
        };
        let _ = writeln!(
            stdout,
            "{:<40} {:<12} {}...",
            pkg.name, pkg.version, hash_display
        );
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg verify
// ---------------------------------------------------------------------------

fn cmd_pkg_verify(
    name: &str,
    version: &str,
    trust_level: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    // Validate trust level.
    if !matches!(
        trust_level,
        "unverified" | "signed" | "verified" | "certified"
    ) {
        let _ = writeln!(
            stderr,
            "Error: invalid trust level '{}'. Must be one of: unverified, signed, verified, certified",
            trust_level
        );
        return ExitCode::ConfigError;
    }

    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg = match store.get(name, version) {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = writeln!(stderr, "Error: package '{}' v{} not found", name, version);
            return ExitCode::Fail;
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(stdout, "Package: {} v{}", name, version);

    // --- Step 1: Local integrity check ---
    let manifest_path = pkg.path.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stdout, "Trust Level: FAIL\n");
            let _ = writeln!(stdout, "  x Content integrity    Missing manifest: {e}");
            return ExitCode::Fail;
        }
    };

    if let Err(e) = parse_pkg_manifest_toml(&manifest_str) {
        let _ = writeln!(stdout, "Trust Level: FAIL\n");
        let _ = writeln!(stdout, "  x Content integrity    Invalid manifest: {e}");
        return ExitCode::Fail;
    }

    let meta_path = pkg.path.join(".pkg-meta.json");
    if !meta_path.exists() {
        let _ = writeln!(stdout, "Trust Level: FAIL\n");
        let _ = writeln!(stdout, "  x Content integrity    Missing store metadata");
        return ExitCode::Fail;
    }

    let metadata = match std::fs::read_to_string(&meta_path)
        .ok()
        .and_then(|s| serde_json::from_str::<StoreMetadata>(&s).ok())
    {
        Some(m) => m,
        None => {
            let _ = writeln!(stdout, "Trust Level: FAIL\n");
            let _ = writeln!(stdout, "  x Content integrity    Invalid store metadata");
            return ExitCode::Fail;
        }
    };

    let installed_at = metadata.installed_at.clone();
    let expected_fingerprint = metadata.content_fingerprint;

    let mut content_ok = true;
    let mut content_error: Option<String> = None;
    let recomputed_fingerprint = match recompute_installed_content_fingerprint(&pkg.path) {
        Ok(h) => h,
        Err(e) => {
            content_ok = false;
            content_error = Some(e);
            Hash::zero()
        }
    };
    if content_ok {
        match expected_fingerprint {
            Some(expected) if recomputed_fingerprint != expected => {
                content_ok = false;
                content_error = Some(format!(
                    "fingerprint mismatch (expected {}..., got {}...)",
                    &expected.to_hex()[..16],
                    &recomputed_fingerprint.to_hex()[..16]
                ));
            }
            Some(_) => {}
            None => {
                content_ok = false;
                content_error = Some(
                    "missing content fingerprint in store metadata; reinstall package".to_string(),
                );
            }
        }
    }

    let fingerprint_hex = recomputed_fingerprint.to_hex();
    let fingerprint_display = if fingerprint_hex.len() > 16 {
        &fingerprint_hex[..16]
    } else {
        &fingerprint_hex
    };

    let mut publisher_ok = false;
    let mut registry_ok = false;
    let mut attestation_error: Option<String> = None;

    // If trust level is unverified, we only check content integrity.
    if trust_level == "unverified" {
        let _ = writeln!(stdout, "Trust Level: Unverified\n");
        if content_ok {
            let _ = writeln!(
                stdout,
                "  + Content integrity    Fingerprint: {}...",
                fingerprint_display
            );
        } else {
            let _ = writeln!(
                stdout,
                "  x Content integrity    {}",
                content_error
                    .as_deref()
                    .unwrap_or("unable to verify local package content")
            );
        }
        let _ = writeln!(stdout, "\nInstalled: {}", installed_at);
        return if content_ok {
            ExitCode::Ok
        } else {
            ExitCode::Fail
        };
    }

    // --- Steps 2-4: Registry-based verification ---
    let cfg = RegistryConfig::load(registry);
    let expected_registry_key = match required_registry_public_key_for_trust(&cfg, trust_level) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(stdout, "Trust Level: x FAIL\n");
            let _ = writeln!(stdout, "  x Registry trust anchor {e}");
            return ExitCode::Fail;
        }
    };
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

    // Fetch attestation.
    let attestation_url = format!(
        "{}/api/v1/packages/{}/{}/attestation",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let attestation: Option<RegistryAttestation> = client
        .get(&attestation_url)
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.json().ok());

    if let Some(ref att) = attestation {
        match verify_attestation_against_hash(att, &pkg.content_hash, expected_registry_key) {
            Ok(v) => {
                publisher_ok = v.publisher_verified;
                registry_ok = v.registry_verified;
            }
            Err(e) => {
                attestation_error = Some(e);
            }
        }
    } else {
        attestation_error = Some("attestation not available from registry".to_string());
    }

    // Fetch and verify Merkle proof (for certified level).
    let proof_url = format!(
        "{}/api/v1/packages/{}/{}/proof",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );
    let mut transparency_ok = false;
    let mut transparency_error: Option<String> = None;
    if let Some(ref att) = attestation {
        match client.get(&proof_url).send() {
            Ok(resp) if resp.status().is_success() => match resp.json::<RegistryProof>() {
                Ok(proof) => {
                    let key_for_proof = expected_registry_key
                        .or(att.registry_key.as_deref())
                        .ok_or_else(|| {
                            "registry key unavailable; cannot verify transparency proof".to_string()
                        });
                    match key_for_proof
                        .and_then(|k| verify_transparency_proof(name, version, att, &proof, k))
                    {
                        Ok(()) => transparency_ok = true,
                        Err(e) => transparency_error = Some(e),
                    }
                }
                Err(e) => transparency_error = Some(format!("invalid proof response: {e}")),
            },
            Ok(resp) => {
                transparency_error = Some(format!(
                    "transparency proof unavailable (HTTP {})",
                    resp.status()
                ))
            }
            Err(e) => transparency_error = Some(format!("cannot fetch transparency proof: {e}")),
        }
    } else {
        transparency_error =
            Some("attestation unavailable; cannot verify transparency proof".to_string());
    }

    // Determine achieved trust level.
    let achieved = if transparency_ok && registry_ok && publisher_ok {
        "Certified"
    } else if registry_ok && publisher_ok {
        "Verified"
    } else if publisher_ok {
        "Signed"
    } else {
        "Unverified"
    };

    // Check if achieved level meets the requested level.
    let level_rank = |l: &str| -> u8 {
        match l.to_lowercase().as_str() {
            "unverified" => 0,
            "signed" => 1,
            "verified" => 2,
            "certified" => 3,
            _ => 0,
        }
    };

    let achieved_rank = level_rank(achieved);
    let required_rank = level_rank(trust_level);
    let meets_requirement = achieved_rank >= required_rank && content_ok;

    let check = if meets_requirement { "+" } else { "x" };
    let _ = writeln!(stdout, "Trust Level: {} {}\n", check, achieved);

    // Print detail lines.
    let mark = |ok: bool| if ok { "+" } else { "x" };

    if content_ok {
        let _ = writeln!(
            stdout,
            "  {} Content integrity    Fingerprint: {}...",
            mark(content_ok),
            fingerprint_display
        );
    } else {
        let _ = writeln!(
            stdout,
            "  {} Content integrity    {}",
            mark(content_ok),
            content_error
                .as_deref()
                .unwrap_or("unable to verify local package content")
        );
    }

    if let Some(ref att) = attestation {
        let pub_key = att.publisher_key.as_str();
        let pub_key_display = if pub_key.len() > 16 {
            &pub_key[..16]
        } else {
            pub_key
        };
        let _ = writeln!(
            stdout,
            "  {} Publisher signature   Key: {}...",
            mark(publisher_ok),
            pub_key_display
        );

        let reg_sig = att.registry_sig.as_deref().unwrap_or("");
        if registry_ok {
            let reg_display = if reg_sig.len() > 16 {
                &reg_sig[..16]
            } else {
                reg_sig
            };
            let _ = writeln!(
                stdout,
                "  {} Registry attestation  Hash: {}...",
                mark(registry_ok),
                reg_display
            );
        } else {
            let _ = writeln!(
                stdout,
                "  {} Registry attestation  Not available",
                mark(registry_ok)
            );
        }

        if let Some(ref err) = attestation_error {
            let _ = writeln!(stdout, "  x Attestation validity  {}", err);
        }
    } else {
        let _ = writeln!(
            stdout,
            "  {} Publisher signature   Not available",
            mark(publisher_ok)
        );
        let _ = writeln!(
            stdout,
            "  {} Registry attestation  Not available",
            mark(registry_ok)
        );
        if let Some(ref err) = attestation_error {
            let _ = writeln!(stdout, "  x Attestation validity  {}", err);
        }
    }

    if transparency_ok {
        let _ = writeln!(
            stdout,
            "  {} Transparency log     Inclusion proof verified",
            mark(transparency_ok)
        );
    } else {
        let detail = transparency_error.as_deref().unwrap_or("Not yet available");
        let _ = writeln!(stdout, "  {} Transparency log     {}", mark(false), detail);
    }

    let _ = writeln!(stdout, "\nInstalled: {}", installed_at);

    if !content_ok {
        let _ = writeln!(stderr, "FAIL: local content integrity check failed");
        ExitCode::Fail
    } else if meets_requirement {
        ExitCode::Ok
    } else {
        let _ = writeln!(
            stderr,
            "FAIL: achieved trust level '{}' does not meet required '{}'",
            achieved.to_lowercase(),
            trust_level
        );
        ExitCode::Fail
    }
}

// ---------------------------------------------------------------------------
// pkg info
// ---------------------------------------------------------------------------

fn cmd_pkg_info(
    name: &str,
    version: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg = match store.get(name, version) {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = writeln!(stderr, "Error: package '{}' v{} not found", name, version);
            return ExitCode::Fail;
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(stdout, "Name:    {}", pkg.name);
    let _ = writeln!(stdout, "Version: {}", pkg.version);
    let _ = writeln!(stdout, "Path:    {}", pkg.path.display());
    let _ = writeln!(stdout, "Hash:    {}", pkg.content_hash);

    // Try to read the manifest for more detail
    let manifest_path = pkg.path.join("clawdstrike-pkg.toml");
    if let Ok(manifest_str) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = parse_pkg_manifest_toml(&manifest_str) {
            let _ = writeln!(stdout, "Type:    {}", manifest.package.pkg_type);
            if let Some(desc) = &manifest.package.description {
                if !desc.is_empty() {
                    let _ = writeln!(stdout, "Desc:    {}", desc);
                }
            }
            if let Some(license) = &manifest.package.license {
                let _ = writeln!(stdout, "License: {}", license);
            }
            if !manifest.package.authors.is_empty() {
                let _ = writeln!(stdout, "Authors: {}", manifest.package.authors.join(", "));
            }
            if !manifest.dependencies.is_empty() {
                let _ = writeln!(stdout, "Dependencies:");
                for (dep_name, constraint) in &manifest.dependencies {
                    let _ = writeln!(stdout, "  {} = \"{}\"", dep_name, constraint);
                }
            }
        }
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg login
// ---------------------------------------------------------------------------

fn cmd_pkg_login(
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

fn cmd_pkg_publish(
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

// ---------------------------------------------------------------------------
// Trusted publishers
// ---------------------------------------------------------------------------

fn cmd_pkg_trusted_publishers(
    command: TrustedPublisherCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        TrustedPublisherCommands::Add {
            package,
            provider,
            repo,
            workflow,
            environment,
            registry,
        } => cmd_trusted_publisher_add(
            &package,
            &provider,
            &repo,
            workflow.as_deref(),
            environment.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        TrustedPublisherCommands::List { package, registry } => {
            cmd_trusted_publisher_list(&package, registry.as_deref(), stdout, stderr)
        }
        TrustedPublisherCommands::Remove {
            package,
            id,
            registry,
        } => cmd_trusted_publisher_remove(&package, id, registry.as_deref(), stdout, stderr),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_trusted_publisher_add(
    package: &str,
    provider: &str,
    repo: &str,
    workflow: Option<&str>,
    environment: Option<&str>,
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

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
    );

    let provider_norm = provider.to_ascii_lowercase();
    let mut body = serde_json::json!({
        "provider": provider_norm,
        "repository": repo,
    });
    if let Some(wf) = workflow {
        body["workflow"] = serde_json::Value::String(wf.to_string());
    }
    if let Some(env) = environment {
        body["environment"] = serde_json::Value::String(env.to_string());
    }

    let payload =
        add_trusted_publisher_signed_payload(package, &provider_norm, repo, workflow, environment);
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(
        stdout,
        "Added trusted publisher for {}: {} ({})",
        package, repo, provider
    );
    ExitCode::Ok
}

fn cmd_trusted_publisher_list(
    package: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

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

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let publishers = resp_json
        .get("trusted_publishers")
        .and_then(|v| v.as_array());

    match publishers {
        Some(list) if !list.is_empty() => {
            let _ = writeln!(stdout, "Trusted publishers for {}:", package);
            for tp in list {
                let id = tp.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                let provider = tp.get("provider").and_then(|v| v.as_str()).unwrap_or("?");
                let repository = tp.get("repository").and_then(|v| v.as_str()).unwrap_or("?");
                let workflow = tp.get("workflow").and_then(|v| v.as_str()).unwrap_or("-");
                let environment = tp
                    .get("environment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let _ = writeln!(
                    stdout,
                    "  [{}] {} {} (workflow: {}, env: {})",
                    id, provider, repository, workflow, environment
                );
            }
        }
        _ => {
            let _ = writeln!(stdout, "No trusted publishers configured for {}.", package);
        }
    }

    ExitCode::Ok
}

fn cmd_trusted_publisher_remove(
    package: &str,
    id: i64,
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

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package),
        id
    );

    let payload = format!("trusted-publisher:remove:{package}:{id}");
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
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Removed trusted publisher {} from {}", id, package);
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg audit
// ---------------------------------------------------------------------------

fn cmd_pkg_audit(
    name: &str,
    registry: Option<&str>,
    limit: u32,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/audit/{}?limit={}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        limit
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

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: audit request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let events = match resp_json.get("events").and_then(|e| e.as_array()) {
        Some(e) => e,
        None => {
            let _ = writeln!(stdout, "No audit events found for '{}'.", name);
            return ExitCode::Ok;
        }
    };

    if events.is_empty() {
        let _ = writeln!(stdout, "No audit events found for '{}'.", name);
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Audit log for: {}\n", name);
    let _ = writeln!(
        stdout,
        "{:<12} {:<10} {:<20} PUBLISHER KEY",
        "VERSION", "ACTION", "TIMESTAMP"
    );
    let _ = writeln!(stdout, "{}", "-".repeat(72));

    for event in events {
        let version = event.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let action = event.get("action").and_then(|a| a.as_str()).unwrap_or("?");
        let timestamp = event
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("?");
        let publisher_key = event
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let key_display = if publisher_key.len() > 16 {
            format!("{}...", &publisher_key[..16])
        } else {
            publisher_key.to_string()
        };

        let _ = writeln!(
            stdout,
            "{:<12} {:<10} {:<20} {}",
            version, action, timestamp, key_display
        );
    }

    let _ = writeln!(stdout, "\n{} event(s) shown.", events.len());
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg stats
// ---------------------------------------------------------------------------

fn cmd_pkg_stats(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/packages/{}/stats",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
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

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: stats request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(name);
    let total_downloads = resp_json
        .get("total_downloads")
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let first_published = resp_json
        .get("first_published")
        .and_then(|f| f.as_str())
        .unwrap_or("unknown");

    let _ = writeln!(stdout, "Package: {}", pkg_name);
    let _ = writeln!(
        stdout,
        "Total downloads: {}",
        format_number(total_downloads)
    );
    let _ = writeln!(stdout, "First published: {}", first_published);

    let versions = resp_json.get("versions").and_then(|v| v.as_array());

    if let Some(versions) = versions {
        if !versions.is_empty() {
            let _ = writeln!(stdout);
            let _ = writeln!(stdout, "  {:<12} {:<12} PUBLISHED", "VERSION", "DOWNLOADS");
            let _ = writeln!(stdout, "  {}", "-".repeat(50));

            for v in versions {
                let version = v.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let downloads = v.get("downloads").and_then(|d| d.as_u64()).unwrap_or(0);
                let published_at = v
                    .get("published_at")
                    .and_then(|p| p.as_str())
                    .unwrap_or("?");
                let _ = writeln!(
                    stdout,
                    "  {:<12} {:<12} {}",
                    version,
                    format_number(downloads),
                    published_at
                );
            }
        }
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg test
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-plugin-runtime")]
fn cmd_pkg_test(
    path: Option<&Path>,
    filter: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    use clawdstrike::pkg::test_runner::{parse_guard_test_file, run_guard_tests};

    let pkg_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    // Discover test fixture files
    let tests_dir = pkg_dir.join("tests");
    if !tests_dir.is_dir() {
        let _ = writeln!(
            stderr,
            "Error: no tests/ directory found in {}",
            pkg_dir.display()
        );
        return ExitCode::ConfigError;
    }

    let fixture_files: Vec<PathBuf> = match std::fs::read_dir(&tests_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect(),
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read tests/ directory: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if fixture_files.is_empty() {
        let _ = writeln!(
            stderr,
            "Error: no .yaml/.yml fixture files found in {}",
            tests_dir.display()
        );
        return ExitCode::ConfigError;
    }

    // Find the WASM file: check plugin manifest entrypoint first, then fall
    // back to conventional target output locations.
    let wasm_path = find_wasm_binary(&pkg_dir, stderr);
    let wasm_path = match wasm_path {
        Some(p) => p,
        None => return ExitCode::ConfigError,
    };

    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Error: cannot read WASM file {}: {e}",
                wasm_path.display()
            );
            return ExitCode::RuntimeError;
        }
    };

    // Load runtime options from plugin manifest if available.
    let options = load_runtime_options(&pkg_dir);

    let _ = writeln!(stdout, "Running guard tests...");
    let _ = writeln!(stdout, "WASM: {}", wasm_path.display());
    let _ = writeln!(stdout);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_error = 0usize;

    for fixture_path in &fixture_files {
        let suite = match parse_guard_test_file(fixture_path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Error: failed to parse {}: {e}",
                    fixture_path.display()
                );
                total_error += 1;
                continue;
            }
        };

        let file_name = fixture_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let _ = writeln!(stdout, "--- {} ({})", suite.suite, file_name);

        let results = run_guard_tests(&wasm_bytes, &suite, &options, filter);

        for result in &results {
            if result.passed {
                total_pass += 1;
                let _ = writeln!(
                    stdout,
                    "  PASS  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
            } else if let Some(ref err) = result.error {
                total_error += 1;
                let _ = writeln!(stdout, "  ERROR {} -- {}", result.name, err);
            } else {
                total_fail += 1;
                let _ = writeln!(
                    stdout,
                    "  FAIL  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
                for mismatch in &result.mismatches {
                    let _ = writeln!(
                        stdout,
                        "         {}: expected '{}', got '{}'",
                        mismatch.field, mismatch.expected, mismatch.actual
                    );
                }
            }
        }

        let _ = writeln!(stdout);
    }

    let _ = writeln!(
        stdout,
        "Results: {} passed, {} failed, {} errors",
        total_pass, total_fail, total_error
    );

    if total_fail > 0 || total_error > 0 {
        ExitCode::Fail
    } else {
        ExitCode::Ok
    }
}

#[cfg(not(feature = "wasm-plugin-runtime"))]
fn cmd_pkg_test(
    _path: Option<&Path>,
    _filter: Option<&str>,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let _ = writeln!(
        stderr,
        "Error: `pkg test` requires the `wasm-plugin-runtime` feature.\n\
         Rebuild with: cargo build --features wasm-plugin-runtime"
    );
    ExitCode::ConfigError
}

#[cfg(feature = "wasm-plugin-runtime")]
fn load_plugin_manifest_from_package(
    pkg_dir: &Path,
) -> Option<(std::path::PathBuf, clawdstrike::plugins::PluginManifest)> {
    use clawdstrike::plugins::parse_plugin_manifest_toml;

    let manifest_path = pkg_dir.join(PLUGIN_MANIFEST_FILENAME);
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(_) => return None,
    };
    if let Ok(manifest) = parse_plugin_manifest_toml(&content) {
        return Some((manifest_path, manifest));
    }

    None
}

#[cfg(feature = "wasm-plugin-runtime")]
fn find_wasm_binary(pkg_dir: &Path, stderr: &mut dyn Write) -> Option<PathBuf> {
    // Try plugin manifest entrypoint first.
    if let Some((_manifest_path, manifest)) = load_plugin_manifest_from_package(pkg_dir) {
        if let Some(entrypoint) = manifest
            .guards
            .first()
            .and_then(|g| g.entrypoint.as_deref())
        {
            let candidate = pkg_dir.join(entrypoint);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        // Fall back to conventional artifact naming from plugin name.
        let fallback_pkg_name = sanitize_cargo_package_name(&manifest.plugin.name);
        let wasm_name = format!("{}.wasm", fallback_pkg_name.replace('-', "_"));
        for profile in &["release", "debug"] {
            let candidate = pkg_dir
                .join("target/wasm32-unknown-unknown")
                .join(profile)
                .join(&wasm_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // Fall back: try to read Cargo.toml for [package].name
    let cargo_path = pkg_dir.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        if let Ok(table) = content.parse::<toml::Table>() {
            if let Some(pkg_name) = table
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                let wasm_name = format!("{}.wasm", pkg_name.replace('-', "_"));
                for profile in &["release", "debug"] {
                    let candidate = pkg_dir
                        .join("target/wasm32-unknown-unknown")
                        .join(profile)
                        .join(&wasm_name);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    // Last resort: find any .wasm file in the target dirs
    for profile in &["release", "debug"] {
        let dir = pkg_dir.join("target/wasm32-unknown-unknown").join(profile);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "wasm") {
                    return Some(p);
                }
            }
        }
    }

    let _ = writeln!(
        stderr,
        "Error: no .wasm file found. Build your guard first:\n  \
         cargo build --target wasm32-unknown-unknown --release"
    );
    None
}

#[cfg(feature = "wasm-plugin-runtime")]
fn load_runtime_options(pkg_dir: &Path) -> clawdstrike::plugins::WasmGuardRuntimeOptions {
    use clawdstrike::plugins::WasmGuardRuntimeOptions;

    if let Some((_manifest_path, manifest)) = load_plugin_manifest_from_package(pkg_dir) {
        return WasmGuardRuntimeOptions {
            capabilities: manifest.capabilities,
            resources: manifest.resources,
        };
    }

    WasmGuardRuntimeOptions::default()
}

// ---------------------------------------------------------------------------
// pkg org
// ---------------------------------------------------------------------------

fn cmd_pkg_org(command: OrgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        OrgCommands::Create {
            name,
            display_name,
            registry,
        } => cmd_org_create(
            &name,
            display_name.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Members { name, registry } => {
            cmd_org_members(&name, registry.as_deref(), stdout, stderr)
        }
        OrgCommands::Invite {
            org,
            publisher_key,
            role,
            registry,
        } => cmd_org_invite(
            &org,
            &publisher_key,
            &role,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Remove {
            org,
            publisher_key,
            registry,
        } => cmd_org_remove(&org, &publisher_key, registry.as_deref(), stdout, stderr),
        OrgCommands::Info { name, registry } => {
            cmd_org_info(&name, registry.as_deref(), stdout, stderr)
        }
    }
}

fn cmd_org_create(
    name: &str,
    display_name: Option<&str>,
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

    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

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

    let url = format!("{}/api/v1/orgs", cfg.registry_url.trim_end_matches('/'));

    let mut body = serde_json::json!({
        "name": name,
        "publisher_key": keypair.public_key().to_hex(),
    });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::Value::String(dn.to_string());
    }
    let payload = format!(
        "org:create:{}:{}:{}",
        name,
        keypair.public_key().to_hex(),
        display_name.unwrap_or("")
    );
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Created organization @{}", name);
    ExitCode::Ok
}

fn cmd_org_members(
    name: &str,
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

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).bearer_auth(&auth_token).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let members = match resp_json.get("members").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => {
            let _ = writeln!(stdout, "No members found.");
            return ExitCode::Ok;
        }
    };

    let _ = writeln!(stdout, "Members of @{}:\n", name);
    let _ = writeln!(stdout, "{:<48} {:<12} JOINED", "KEY", "ROLE");
    let _ = writeln!(stdout, "{}", "-".repeat(80));

    for member in members {
        let key = member
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let role = member.get("role").and_then(|r| r.as_str()).unwrap_or("?");
        let joined = member
            .get("joined_at")
            .and_then(|j| j.as_str())
            .unwrap_or("?");
        let key_display = if key.len() > 44 {
            format!("{}...", &key[..44])
        } else {
            key.to_string()
        };
        let _ = writeln!(stdout, "{:<48} {:<12} {}", key_display, role, joined);
    }

    let _ = writeln!(stdout, "\n{} member(s)", members.len());
    ExitCode::Ok
}

fn cmd_org_invite(
    org: &str,
    publisher_key: &str,
    role: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if !matches!(role, "owner" | "maintainer" | "member") {
        let _ = writeln!(
            stderr,
            "Error: invalid role '{}'. Must be one of: owner, maintainer, member",
            role
        );
        return ExitCode::ConfigError;
    }

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

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org)
    );

    let body = serde_json::json!({
        "publisher_key": publisher_key,
        "role": role,
    });

    let payload = format!("org:invite:{org}:{publisher_key}:{role}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Invited {} to @{} as {}", publisher_key, org, role);
    ExitCode::Ok
}

fn cmd_org_remove(
    org: &str,
    publisher_key: &str,
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

    let url = format!(
        "{}/api/v1/orgs/{}/members/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org),
        urlencoding_simple(publisher_key)
    );

    let payload = format!("org:remove:{org}:{publisher_key}");
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
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Removed {} from @{}", publisher_key, org);
    ExitCode::Ok
}

fn cmd_org_info(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

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

    let url = format!(
        "{}/api/v1/orgs/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let org_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("?");
    let display = resp_json
        .get("display_name")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let verified = resp_json
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let members = resp_json
        .get("member_count")
        .and_then(|m| m.as_i64())
        .unwrap_or(0);
    let packages = resp_json
        .get("package_count")
        .and_then(|p| p.as_i64())
        .unwrap_or(0);

    let _ = writeln!(stdout, "Organization: @{}", org_name);
    if !display.is_empty() {
        let _ = writeln!(stdout, "Display Name: {}", display);
    }
    let _ = writeln!(
        stdout,
        "Verified:     {}",
        if verified { "yes" } else { "no" }
    );
    let _ = writeln!(stdout, "Members:      {}", members);
    let _ = writeln!(stdout, "Packages:     {}", packages);

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cmd(cmd: PkgCommands) -> (String, String, ExitCode) {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let code = cmd_pkg(cmd, &mut stdout_buf, &mut stderr_buf);
        (
            String::from_utf8_lossy(&stdout_buf).to_string(),
            String::from_utf8_lossy(&stderr_buf).to_string(),
            code,
        )
    }

    #[test]
    fn test_scaffold_guard() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-test-guard").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("src").is_dir());

        let content = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(content.contains("my-test-guard"));
        assert!(content.contains("guard"));
    }

    #[test]
    fn test_scaffold_guard_creates_all_template_files() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-guard").unwrap();

        // Guard-specific files
        assert!(tmp.path().join("src/lib.rs").exists());
        assert!(tmp.path().join("Cargo.toml").exists());
        assert!(tmp.path().join("clawdstrike.plugin.toml").exists());
        assert!(tmp.path().join("tests/basic.yaml").exists());
        assert!(tmp.path().join(".cargo/config.toml").exists());

        // Verify content of key files
        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("clawdstrike_guard_sdk"));
        assert!(lib_rs.contains("#[clawdstrike_guard]"));
        assert!(lib_rs.contains("impl Guard for"));

        let cargo_toml = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("cdylib"));
        assert!(cargo_toml.contains("clawdstrike-guard-sdk"));

        let plugin_manifest =
            std::fs::read_to_string(tmp.path().join("clawdstrike.plugin.toml")).unwrap();
        assert!(plugin_manifest.contains("my-guard"));
        assert!(plugin_manifest
            .contains("entrypoint = \"target/wasm32-unknown-unknown/release/my_guard.wasm\""));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/basic.yaml")).unwrap();
        assert!(test_yaml.contains("my-guard"));
        assert!(test_yaml.contains("fixtures:"));

        let cargo_config = std::fs::read_to_string(tmp.path().join(".cargo/config.toml")).unwrap();
        assert!(cargo_config.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn test_scaffold_guard_struct_name_derivation() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "@acme/my-cool-guard").unwrap();

        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        // @acme/my-cool-guard -> AcmeMyCoolGuardGuard
        assert!(lib_rs.contains("AcmeMyCoolGuardGuard"));

        let cargo_toml = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("name = \"acme-my-cool-guard\""));

        let plugin_manifest =
            std::fs::read_to_string(tmp.path().join("clawdstrike.plugin.toml")).unwrap();
        assert!(plugin_manifest.contains(
            "entrypoint = \"target/wasm32-unknown-unknown/release/acme_my_cool_guard.wasm\""
        ));
    }

    #[test]
    fn test_scaffold_non_guard_skips_guard_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(!tmp.path().join("src/lib.rs").exists());
        assert!(!tmp.path().join("clawdstrike.plugin.toml").exists());
        assert!(!tmp.path().join("tests/basic.yaml").exists());
    }

    #[test]
    fn test_scaffold_policy_pack() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
    }

    #[test]
    fn test_scaffold_all_types() {
        for (pkg_type, expected_dir) in [
            (PkgType::Guard, Some("src")),
            (PkgType::PolicyPack, Some("policies")),
            (PkgType::Adapter, Some("src")),
            (PkgType::Engine, Some("src")),
            (PkgType::Template, Some("template")),
            (PkgType::Bundle, None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            scaffold_package(tmp.path(), &pkg_type, "test-pkg").unwrap();
            assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
            if let Some(dir) = expected_dir {
                assert!(
                    tmp.path().join(dir).is_dir(),
                    "expected {dir} for {pkg_type}"
                );
            }
        }
    }

    #[test]
    fn test_pack_missing_manifest() {
        let tmp = tempfile::tempdir().unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("clawdstrike-pkg.toml"));
    }

    #[test]
    fn test_pack_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("mypkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
        std::fs::write(pkg_dir.join("src/lib.rs"), "// guard code").unwrap();

        let (stdout, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(pkg_dir.clone()),
        });

        assert_eq!(code, ExitCode::Ok, "stderr: {}", stderr);
        assert!(stdout.contains("Packed:"));
        assert!(stdout.contains("Hash:"));

        // Verify .cpkg file exists
        let cpkg = pkg_dir.join("test-pkg-0.1.0.cpkg");
        assert!(cpkg.exists(), "expected cpkg at {}", cpkg.display());
    }

    #[test]
    fn test_pack_excludes_existing_cpkg_files_from_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("mypkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
        std::fs::write(pkg_dir.join("src/lib.rs"), "// guard code").unwrap();
        std::fs::write(pkg_dir.join("stale-build.cpkg"), b"stale").unwrap();

        let (_stdout, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(pkg_dir.clone()),
        });
        assert_eq!(code, ExitCode::Ok, "stderr: {stderr}");

        let cpkg = pkg_dir.join("test-pkg-0.1.0.cpkg");
        let unpacked = tmp.path().join("unpacked");
        archive::unpack(&cpkg, &unpacked).unwrap();

        assert!(!unpacked.join("stale-build.cpkg").exists());
        assert!(unpacked.join("src/lib.rs").exists());
    }

    #[test]
    fn test_list_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let _ = store; // ensure store dir exists

        // We can't easily redirect the default store, so just verify
        // the list command doesn't panic with an empty store.
        // Direct testing would require a way to inject the store root.
    }

    #[test]
    fn test_install_nonexistent() {
        let (_, stderr, code) = run_cmd(PkgCommands::Install {
            source: "/tmp/nonexistent-pkg-12345.cpkg".to_string(),
            version: None,
            registry: None,
            trust_level: Some("signed".to_string()),
            allow_unverified: false,
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not found"));
    }

    #[test]
    fn test_local_install_requires_explicit_unverified_opt_in() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("local-install");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "local-install-test"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "ok").unwrap();
        let archive_path = tmp.path().join("local-install-test-0.1.0.cpkg");
        archive::pack(&src, &archive_path).unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Install {
            source: archive_path.to_string_lossy().to_string(),
            version: None,
            registry: None,
            trust_level: Some("signed".to_string()),
            allow_unverified: false,
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("--allow-unverified"));
        assert!(stderr.contains("registry"));
    }

    #[test]
    fn test_is_file_source() {
        // File paths
        assert!(is_file_source("/tmp/my-pkg.cpkg"));
        assert!(is_file_source("./local-pkg.cpkg"));
        assert!(is_file_source("../other.cpkg"));
        assert!(is_file_source("/absolute/path/to/pkg.cpkg"));

        // Package names (not file paths)
        assert!(!is_file_source("@acme/my-guard"));
        assert!(!is_file_source("my-guard"));
        assert!(!is_file_source("@scope/name"));
    }

    #[test]
    fn test_registry_config_defaults() {
        let cfg = RegistryConfig::from_toml_str("", "");
        assert_eq!(cfg.registry_url, "http://localhost:3100");
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn test_registry_config_from_toml() {
        let config = r#"
[registry]
url = "https://registry.example.com"
"#;
        let creds = r#"
[registry]
auth_token = "tok_secret"
"#;
        let cfg = RegistryConfig::from_toml_str(config, creds);
        assert_eq!(cfg.registry_url, "https://registry.example.com");
        assert_eq!(cfg.auth_token.as_deref(), Some("tok_secret"));
    }

    #[test]
    fn test_urlencoding_simple() {
        assert_eq!(urlencoding_simple("hello"), "hello");
        assert_eq!(urlencoding_simple("@scope/name"), "%40scope%2Fname");
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("foo+bar"), "foo%2Bbar");
    }

    #[test]
    fn test_truncate_with_ellipsis_handles_utf8_boundaries() {
        let input = "naive cafe from a roastery with emoji cafe";
        assert_eq!(truncate_with_ellipsis(input, 12), "naive cafe f...");

        let unicode_input = "naive cafe 日本語で説明する";
        assert_eq!(
            truncate_with_ellipsis(unicode_input, 12),
            "naive cafe 日..."
        );
    }

    #[test]
    fn test_publish_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Publish {
            path: Some(tmp.path().to_path_buf()),
            // Use a fake registry so we never actually hit a real server
            registry: Some("http://127.0.0.1:1".to_string()),
            oidc: false,
        });

        // Should fail because no auth token is configured
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not authenticated"));
    }

    // -----------------------------------------------------------------------
    // Enhanced scaffolding template tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scaffold_policy_pack_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "@acme/my-policies").unwrap();

        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
        assert!(tmp.path().join("tests").is_dir());
        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies/default.yaml").exists());
        assert!(tmp.path().join("tests/policy-test.yaml").exists());
        assert!(tmp.path().join("README.md").exists());

        let policy = std::fs::read_to_string(tmp.path().join("policies/default.yaml")).unwrap();
        assert!(policy.contains("version:"));
        assert!(policy.contains("guards:"));
        assert!(policy.contains("forbidden_path:"));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/policy-test.yaml")).unwrap();
        assert!(test_yaml.contains("tests:"));
        assert!(test_yaml.contains("file_access"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("@acme/my-policies"));
    }

    #[test]
    fn test_scaffold_bundle_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Bundle, "my-bundle").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("README.md").exists());

        let manifest = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(manifest.contains("[dependencies]"));
        assert!(manifest.contains("bundle"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("bundle"));
        assert!(readme.contains("my-bundle"));
    }

    // -----------------------------------------------------------------------
    // Pre-pack validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_pack_missing_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("policies/ directory"));
    }

    #[test]
    fn test_validate_policy_pack_empty_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one .yaml"));
    }

    #[test]
    fn test_validate_policy_pack_with_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        std::fs::write(tmp.path().join("policies/test.yaml"), "version: \"1.2.0\"").unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_validate_guard_missing_src() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-guard"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src/lib.rs"));
    }

    #[test]
    fn test_validate_bundle_empty_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[dependencies]"));
    }

    #[test]
    fn test_validate_bundle_with_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"@acme/guard" = "^0.1"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_pack_policy_pack_without_policies_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-policies"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("policies/ directory"));
    }

    #[test]
    fn test_pack_guard_without_src_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-src"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("src/lib.rs"));
    }

    #[test]
    fn install_requested_identity_mismatch_is_detected() {
        let installed = clawdstrike::pkg::store::InstalledPackage {
            name: "actual".to_string(),
            version: "1.2.3".to_string(),
            path: std::path::PathBuf::from("/tmp/actual"),
            content_hash: hush_core::sha256(b"abc"),
        };
        assert!(!requested_identity_matches_install(
            "expected", "1.2.3", &installed
        ));
        assert!(!requested_identity_matches_install(
            "actual", "9.9.9", &installed
        ));
        assert!(requested_identity_matches_install(
            "actual", "1.2.3", &installed
        ));
    }

    #[test]
    fn read_archive_identity_returns_manifest_name_and_version() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "identity-demo"
version = "1.2.3"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "ok").unwrap();
        let archive_path = tmp.path().join("identity-demo-1.2.3.cpkg");
        archive::pack(&src, &archive_path).unwrap();

        let (name, version) = read_archive_identity(&archive_path).unwrap();
        assert_eq!(name, "identity-demo");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn select_default_registry_version_chooses_newest_non_yanked() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "1.9.8", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
                { "version": "1.9.9", "yanked": false, "published_at": "2026-02-01T00:00:00Z" },
                { "version": "2.0.0", "yanked": true, "published_at": "2026-03-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("1.9.9")
        );
    }

    #[test]
    fn select_default_registry_version_prefers_latest_hint_when_allowed() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "1.0.0", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
                { "version": "2.0.0", "yanked": false, "published_at": "2026-02-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("2.0.0")
        );
    }

    #[test]
    fn select_default_registry_version_returns_none_when_all_yanked() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "2.0.0", "yanked": true },
                { "version": "1.9.9", "yanked": true }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(select_default_registry_version(&stats), None);
    }

    #[test]
    fn select_default_registry_version_fails_closed_without_yank_state() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "2.0.0", "published_at": "2026-03-01T00:00:00Z" },
                { "version": "1.9.9", "published_at": "2026-02-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(select_default_registry_version(&stats), None);
    }

    #[test]
    fn select_default_registry_version_falls_back_when_versions_missing() {
        let stats = serde_json::json!({
            "latest_version": "1.4.2"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("1.4.2")
        );
    }

    #[test]
    fn rollback_backup_restores_previous_install_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let install_path = tmp.path().join("pkg").join("1.0.0");
        std::fs::create_dir_all(&install_path).unwrap();
        std::fs::write(install_path.join("marker.txt"), b"old").unwrap();

        let installed = clawdstrike::pkg::store::InstalledPackage {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            path: install_path.clone(),
            content_hash: hush_core::sha256(b"old"),
        };

        let backup = create_install_rollback_backup(Some(&installed))
            .unwrap()
            .expect("backup should exist");
        assert!(backup.backup_path.exists());

        std::fs::remove_dir_all(&install_path).unwrap();
        std::fs::create_dir_all(&install_path).unwrap();
        std::fs::write(install_path.join("marker.txt"), b"new").unwrap();

        restore_install_from_backup(&backup).unwrap();

        let restored = std::fs::read(install_path.join("marker.txt")).unwrap();
        assert_eq!(restored, b"old");
        assert!(!backup.backup_path.exists());
    }

    #[test]
    fn recompute_installed_content_fingerprint_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "verify-demo"
version = "1.0.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "hello").unwrap();
        let archive_path = tmp.path().join("verify-demo-1.0.0.cpkg");
        let archive_hash = clawdstrike::pkg::archive::pack(&src, &archive_path).unwrap();

        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let installed = store.install_from_file(&archive_path).unwrap();
        assert_eq!(installed.content_hash, archive_hash);

        let meta: StoreMetadata = serde_json::from_str(
            &std::fs::read_to_string(installed.path.join(".pkg-meta.json")).unwrap(),
        )
        .unwrap();
        let expected = meta.content_fingerprint.unwrap();

        let recomputed = recompute_installed_content_fingerprint(&installed.path).unwrap();
        assert_eq!(recomputed, expected);

        std::fs::write(installed.path.join("README.md"), "tampered").unwrap();
        let tampered = recompute_installed_content_fingerprint(&installed.path).unwrap();
        assert_ne!(tampered, expected);
    }

    #[test]
    fn certified_transparency_verification_rejects_tampered_proof() {
        let registry = hush_core::Keypair::from_seed(&[77u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let proof = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(root.as_str(), proof.tree_size, checkpoint_timestamp)
                    .as_bytes(),
            )
            .to_hex();
        let mut tampered_hashes = proof.proof_path.clone();
        if tampered_hashes.is_empty() {
            tampered_hashes.push("00".repeat(32));
        } else {
            tampered_hashes[0] = "00".repeat(32);
        }

        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            hashes: tampered_hashes,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("merkle inclusion proof verification failed"));
    }

    #[test]
    fn certified_transparency_verification_accepts_valid_proof() {
        let registry = hush_core::Keypair::from_seed(&[78u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(
                    root.as_str(),
                    inclusion.tree_size,
                    checkpoint_timestamp,
                )
                .as_bytes(),
            )
            .to_hex();

        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap();
    }

    #[test]
    fn certified_transparency_verification_rejects_checkpoint_key_mismatch() {
        let trusted_registry = hush_core::Keypair::from_seed(&[79u8; 32]);
        let proof_signer = hush_core::Keypair::from_seed(&[80u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = proof_signer
            .sign(
                checkpoint_signature_message(
                    root.as_str(),
                    inclusion.tree_size,
                    checkpoint_timestamp,
                )
                .as_bytes(),
            )
            .to_hex();
        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(trusted_registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(proof_signer.public_key().to_hex()),
        };
        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &trusted_registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("checkpoint key does not match"));
    }

    #[test]
    fn certified_transparency_verification_rejects_invalid_checkpoint_timestamp() {
        let registry = hush_core::Keypair::from_seed(&[81u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let bad_timestamp = "not-a-timestamp";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(root.as_str(), inclusion.tree_size, bad_timestamp)
                    .as_bytes(),
            )
            .to_hex();
        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(bad_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };
        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("invalid checkpoint timestamp"));
    }
}
