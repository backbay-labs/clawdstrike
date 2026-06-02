//! Registry-backed `pkg install` path: resolve the install version from
//! package metadata, download the `.cpkg` under a size limit, then hand off to
//! the shared identity/rollback/trust machinery in the parent `install` module.

use std::io::{Read as IoRead, Write};

use clawdstrike::pkg::store::PackageStore;

use super::{
    cleanup_install_backup, create_install_rollback_backup, read_archive_identity,
    requested_identity_matches_install, restore_install_from_backup,
};
use crate::pkg_cli::trust::{verify_install_trust, InstalledIdentity};
use crate::pkg_cli::util::{tempdir_for_download, urlencoding_simple};
use crate::pkg_cli::MAX_REGISTRY_DOWNLOAD_BYTES;
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

pub(in crate::pkg_cli) fn select_default_registry_version(
    info: &serde_json::Value,
) -> Option<String> {
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

pub(super) fn cmd_pkg_install_registry(
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
