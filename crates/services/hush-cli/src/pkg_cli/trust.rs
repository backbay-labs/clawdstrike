//! Registry trust verification: attestation + Merkle transparency proof checks
//! shared by `pkg install` (registry path) and `pkg verify`.

use std::io::Write;

use hush_core::{PublicKey, Signature};

use clawdstrike::pkg::merkle::{verify_inclusion_proof, InclusionProof, LeafData};

use super::util::urlencoding_simple;
use crate::registry_config::RegistryConfig;

/// Verify trust level of a registry-installed package.
/// Returns `true` if trust verification passes at the requested level.
#[derive(Debug, serde::Deserialize)]
pub(super) struct RegistryAttestation {
    pub(super) checksum: String,
    pub(super) publisher_key: String,
    pub(super) publisher_sig: String,
    pub(super) registry_sig: Option<String>,
    pub(super) registry_key: Option<String>,
    #[serde(default)]
    pub(super) published_at: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RegistryProof {
    pub(super) leaf_index: u64,
    pub(super) tree_size: u64,
    pub(super) hashes: Vec<String>,
    #[serde(default)]
    pub(super) root: Option<String>,
    #[serde(default)]
    pub(super) checkpoint_timestamp: Option<String>,
    #[serde(default)]
    pub(super) checkpoint_sig: Option<String>,
    #[serde(default)]
    pub(super) checkpoint_key: Option<String>,
}

#[derive(Debug)]
pub(super) struct AttestationVerification {
    pub(super) publisher_verified: bool,
    pub(super) registry_verified: bool,
    registry_key: Option<String>,
}

pub(super) fn checkpoint_signature_message(root: &str, tree_size: u64, timestamp: &str) -> String {
    format!("clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}")
}

pub(super) fn verify_attestation_against_hash(
    attestation: &RegistryAttestation,
    content_hash: &hush_core::Hash,
    expected_registry_key: Option<&str>,
) -> Result<AttestationVerification, String> {
    if attestation.checksum != content_hash.to_hex() {
        return Err("attestation checksum does not match installed package hash".to_string());
    }

    let publisher_key = PublicKey::from_hex(&attestation.publisher_key)
        .map_err(|e| format!("invalid publisher key in attestation: {e}"))?;
    let publisher_sig = Signature::from_hex(&attestation.publisher_sig)
        .map_err(|e| format!("invalid publisher signature in attestation: {e}"))?;
    if !publisher_key.verify(content_hash.as_bytes(), &publisher_sig) {
        return Err("publisher signature verification failed".to_string());
    }

    let (registry_verified, registry_key) =
        if let Some(registry_sig_hex) = &attestation.registry_sig {
            let registry_key_hex = attestation
                .registry_key
                .as_deref()
                .ok_or_else(|| "registry signature present but registry key missing".to_string())?;
            let Some(expected) = expected_registry_key else {
                return Ok(AttestationVerification {
                    publisher_verified: true,
                    registry_verified: false,
                    registry_key: Some(registry_key_hex.to_string()),
                });
            };
            if expected != registry_key_hex {
                return Err(
                    "attestation registry key does not match configured trust anchor".to_string(),
                );
            }
            let registry_key = PublicKey::from_hex(registry_key_hex)
                .map_err(|e| format!("invalid registry key in attestation: {e}"))?;
            let registry_sig = Signature::from_hex(registry_sig_hex)
                .map_err(|e| format!("invalid registry signature in attestation: {e}"))?;
            if !registry_key.verify(content_hash.as_bytes(), &registry_sig) {
                return Err("registry counter-signature verification failed".to_string());
            }
            (true, Some(registry_key_hex.to_string()))
        } else {
            (false, None)
        };

    Ok(AttestationVerification {
        publisher_verified: true,
        registry_verified,
        registry_key,
    })
}

fn verify_checkpoint_signature(
    root: &str,
    tree_size: u64,
    timestamp: &str,
    sig_hex: &str,
    key_hex: &str,
) -> Result<(), String> {
    hush_core::Hash::from_hex(root).map_err(|e| format!("invalid checkpoint root hex: {e}"))?;
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|e| format!("invalid checkpoint timestamp: {e}"))?;

    let key = PublicKey::from_hex(key_hex).map_err(|e| format!("invalid checkpoint key: {e}"))?;
    let sig =
        Signature::from_hex(sig_hex).map_err(|e| format!("invalid checkpoint signature: {e}"))?;
    let message = checkpoint_signature_message(root, tree_size, timestamp);
    if key.verify(message.as_bytes(), &sig) {
        Ok(())
    } else {
        Err("checkpoint signature verification failed".to_string())
    }
}

pub(super) fn verify_transparency_proof(
    name: &str,
    version: &str,
    attestation: &RegistryAttestation,
    proof: &RegistryProof,
    expected_registry_key: &str,
) -> Result<(), String> {
    let root = proof
        .root
        .as_deref()
        .ok_or_else(|| "proof response missing root".to_string())?;
    let checkpoint_timestamp = proof
        .checkpoint_timestamp
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint timestamp".to_string())?;
    let checkpoint_sig = proof
        .checkpoint_sig
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint signature".to_string())?;
    let checkpoint_key = proof
        .checkpoint_key
        .as_deref()
        .ok_or_else(|| "proof response missing checkpoint key".to_string())?;
    if checkpoint_key != expected_registry_key {
        return Err(
            "proof checkpoint key does not match configured/attested registry key".to_string(),
        );
    }
    verify_checkpoint_signature(
        root,
        proof.tree_size,
        checkpoint_timestamp,
        checkpoint_sig,
        checkpoint_key,
    )?;

    let timestamp = attestation
        .published_at
        .as_deref()
        .ok_or_else(|| "attestation missing published_at timestamp".to_string())?;
    let leaf_data = LeafData {
        package_name: name.to_string(),
        version: version.to_string(),
        content_hash: attestation.checksum.clone(),
        publisher_key: attestation.publisher_key.clone(),
        timestamp: timestamp.to_string(),
    };
    let leaf_hash = leaf_data
        .leaf_hash()
        .map_err(|e| format!("failed to build transparency leaf hash: {e}"))?
        .to_hex();
    let inclusion = InclusionProof {
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        proof_path: proof.hashes.clone(),
    };
    if verify_inclusion_proof(&inclusion, &leaf_hash, root) {
        Ok(())
    } else {
        Err("merkle inclusion proof verification failed".to_string())
    }
}

pub(super) struct InstalledIdentity<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) content_hash: &'a hush_core::Hash,
}

pub(super) fn required_registry_public_key_for_trust<'a>(
    cfg: &'a RegistryConfig,
    trust_level: &str,
) -> Result<Option<&'a str>, String> {
    if matches!(trust_level, "verified" | "certified") {
        cfg.registry_public_key
            .as_deref()
            .ok_or_else(|| {
                "registry public key trust anchor is required for verified/certified trust; \
                 set [registry].public_key or CLAWDSTRIKE_REGISTRY_PUBLIC_KEY"
                    .to_string()
            })
            .map(Some)
    } else {
        Ok(None)
    }
}

pub(super) fn verify_install_trust(
    installed: InstalledIdentity<'_>,
    cfg: &RegistryConfig,
    client: &reqwest::blocking::Client,
    trust_level: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    let _ = writeln!(stdout, "Verifying trust level: {} ...", trust_level);
    let expected_registry_key = match required_registry_public_key_for_trust(cfg, trust_level) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return false;
        }
    };

    // Fetch attestation from registry.
    let attestation_url = format!(
        "{}/api/v1/packages/{}/{}/attestation",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(installed.name),
        urlencoding_simple(installed.version)
    );

    let resp = match client.get(&attestation_url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Warning: cannot fetch attestation: {e}");
            return false;
        }
    };

    if !resp.status().is_success() {
        let _ = writeln!(
            stderr,
            "Warning: attestation not available (HTTP {})",
            resp.status()
        );
        return false;
    }

    let attestation: RegistryAttestation = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Warning: invalid attestation response: {e}");
            return false;
        }
    };

    let verified = match verify_attestation_against_hash(
        &attestation,
        installed.content_hash,
        expected_registry_key,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return false;
        }
    };

    if trust_level == "signed" {
        return verified.publisher_verified;
    }

    if !verified.registry_verified {
        let _ = writeln!(
            stderr,
            "Error: package has no valid registry counter-signature"
        );
        return false;
    }

    if trust_level == "verified" {
        return true;
    }

    // At "certified" level, we also need a Merkle inclusion proof.
    let proof_url = format!(
        "{}/api/v1/packages/{}/{}/proof",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(installed.name),
        urlencoding_simple(installed.version)
    );

    let proof_resp = match client.get(&proof_url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot fetch inclusion proof: {e}");
            return false;
        }
    };

    if !proof_resp.status().is_success() {
        let _ = writeln!(
            stderr,
            "Error: Merkle inclusion proof not available (HTTP {})",
            proof_resp.status()
        );
        return false;
    }

    let proof: RegistryProof = match proof_resp.json() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid proof response: {e}");
            return false;
        }
    };

    let registry_key = match expected_registry_key.or(verified.registry_key.as_deref()) {
        Some(k) => k,
        None => {
            let _ = writeln!(
                stderr,
                "Error: registry key unavailable for transparency verification"
            );
            return false;
        }
    };
    match verify_transparency_proof(
        installed.name,
        installed.version,
        &attestation,
        &proof,
        registry_key,
    ) {
        Ok(()) => true,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            false
        }
    }
}
