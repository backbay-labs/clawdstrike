//! TPM2 sealing helpers (best-effort).
//!
//! This module provides a pragmatic TPM2 integration via `tpm2-tools`:
//! - Seal arbitrary bytes into the TPM
//! - Unseal later to retrieve the bytes
//!
//! Notes:
//! - This is a best-effort implementation and depends on external binaries being available.
//! - Secrets are written to temporary files during seal/unseal and are deleted afterward.
//! - The blob format stores TPM public/private parts as hex strings.

use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::signing::{Keypair, PublicKey, Signature, Signer};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmSealedBlob {
    pub version: u8,
    pub expected_len: usize,
    pub tpm_public_hex: String,
    pub tpm_private_hex: String,
}

impl TpmSealedBlob {
    pub fn seal(secret: &[u8]) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::TpmError("refusing to seal empty secret".to_string()));
        }

        let temp = tempfile::tempdir().map_err(|e| Error::IoError(e.to_string()))?;
        let seed_path = temp.path().join("secret.bin");
        std::fs::write(&seed_path, secret)?;

        let primary_ctx = temp.path().join("primary.ctx");
        let sealed_pub = temp.path().join("sealed.pub");
        let sealed_priv = temp.path().join("sealed.priv");

        let primary_ctx_str = primary_ctx
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let sealed_pub_str = sealed_pub
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let sealed_priv_str = sealed_priv
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let seed_path_str = seed_path
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;

        let mut create_primary = Command::new("tpm2_createprimary");
        create_primary.args(["-C", "o", "-c", primary_ctx_str]);
        run_checked(create_primary, "tpm2_createprimary")?;

        let mut create = Command::new("tpm2_create");
        create.args([
            "-C",
            primary_ctx_str,
            "-u",
            sealed_pub_str,
            "-r",
            sealed_priv_str,
            "-i",
            seed_path_str,
        ]);
        run_checked(create, "tpm2_create")?;

        // Best-effort cleanup of transient contexts.
        let _ = Command::new("tpm2_flushcontext")
            .args([
                primary_ctx
                    .to_str()
                    .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?,
            ])
            .output();

        let pub_bytes = std::fs::read(&sealed_pub)?;
        let priv_bytes = std::fs::read(&sealed_priv)?;

        Ok(Self {
            version: 1,
            expected_len: secret.len(),
            tpm_public_hex: hex::encode(pub_bytes),
            tpm_private_hex: hex::encode(priv_bytes),
        })
    }

    pub fn unseal(&self) -> Result<Vec<u8>> {
        if self.version != 1 {
            return Err(Error::TpmError(format!(
                "unsupported sealed blob version: {}",
                self.version
            )));
        }

        if self.expected_len == 0 {
            return Err(Error::TpmError(
                "sealed blob has expected_len=0".to_string(),
            ));
        }

        let pub_bytes =
            hex::decode(&self.tpm_public_hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
        let priv_bytes =
            hex::decode(&self.tpm_private_hex).map_err(|e| Error::InvalidHex(e.to_string()))?;

        let temp = tempfile::tempdir().map_err(|e| Error::IoError(e.to_string()))?;
        let primary_ctx = temp.path().join("primary.ctx");
        let sealed_pub = temp.path().join("sealed.pub");
        let sealed_priv = temp.path().join("sealed.priv");
        let sealed_ctx = temp.path().join("sealed.ctx");

        std::fs::write(&sealed_pub, pub_bytes)?;
        std::fs::write(&sealed_priv, priv_bytes)?;

        let primary_ctx_str = primary_ctx
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let sealed_pub_str = sealed_pub
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let sealed_priv_str = sealed_priv
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;
        let sealed_ctx_str = sealed_ctx
            .to_str()
            .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?;

        let mut create_primary = Command::new("tpm2_createprimary");
        create_primary.args(["-C", "o", "-c", primary_ctx_str]);
        run_checked(create_primary, "tpm2_createprimary")?;

        let mut load = Command::new("tpm2_load");
        load.args([
            "-C",
            primary_ctx_str,
            "-u",
            sealed_pub_str,
            "-r",
            sealed_priv_str,
            "-c",
            sealed_ctx_str,
        ]);
        run_checked(load, "tpm2_load")?;

        let mut unseal = Command::new("tpm2_unseal");
        unseal.args(["-c", sealed_ctx_str]);
        let mut out = run_checked(unseal, "tpm2_unseal")?;

        // Best-effort cleanup of transient contexts.
        let _ = Command::new("tpm2_flushcontext")
            .args([
                sealed_ctx
                    .to_str()
                    .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?,
            ])
            .output();
        let _ = Command::new("tpm2_flushcontext")
            .args([
                primary_ctx
                    .to_str()
                    .ok_or_else(|| Error::TpmError("temp path not utf-8".to_string()))?,
            ])
            .output();

        if out.len() > self.expected_len {
            out.truncate(self.expected_len);
        }

        if out.len() != self.expected_len {
            return Err(Error::TpmError(format!(
                "unsealed secret length mismatch: expected {}, got {}",
                self.expected_len,
                out.len()
            )));
        }

        Ok(out)
    }
}

/// A `Signer` implementation backed by a TPM-sealed Ed25519 seed.
///
/// This unseals the seed on each `sign()` call, constructs an in-memory `Keypair`,
/// signs, then drops the key material.
#[derive(Clone, Debug)]
pub struct TpmSealedSeedSigner {
    pub public_key: PublicKey,
    pub blob: TpmSealedBlob,
}

impl TpmSealedSeedSigner {
    pub fn new(public_key: PublicKey, blob: TpmSealedBlob) -> Self {
        Self { public_key, blob }
    }

    fn unseal_seed(&self) -> Result<[u8; 32]> {
        let bytes = self.blob.unseal()?;
        let len = bytes.len();
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::TpmError(format!(
                "expected unsealed Ed25519 seed to be 32 bytes, got {}",
                len
            ))
        })?;
        Ok(bytes)
    }
}

impl Signer for TpmSealedSeedSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let seed = self.unseal_seed()?;
        let keypair = Keypair::from_seed(&seed);
        Ok(keypair.sign(message))
    }
}

fn run_checked(mut cmd: Command, name: &'static str) -> Result<Vec<u8>> {
    let output = cmd.output().map_err(|e| {
        Error::TpmError(format!(
            "{} failed to execute (is tpm2-tools installed?): {}",
            name, e
        ))
    })?;

    if !output.status.success() {
        return Err(Error::TpmError(format!(
            "{} failed: status={} stderr={}",
            name,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(output.stdout)
}
