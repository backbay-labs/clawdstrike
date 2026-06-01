//! `pkg list`, `pkg verify`, and `pkg info` — inspect installed packages
//! and verify their integrity and registry trust level.

use std::io::Write;

use hush_core::Hash;

use clawdstrike::pkg::manifest::parse_pkg_manifest_toml;
use clawdstrike::pkg::store::{PackageStore, StoreMetadata};

use super::install::recompute_installed_content_fingerprint;
use super::trust::{
    required_registry_public_key_for_trust, verify_attestation_against_hash,
    verify_transparency_proof, RegistryAttestation, RegistryProof,
};
use super::util::urlencoding_simple;
use crate::registry_config::RegistryConfig;
use crate::ExitCode;

pub(super) fn cmd_pkg_list(stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
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

pub(super) fn cmd_pkg_verify(
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

pub(super) fn cmd_pkg_info(
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
