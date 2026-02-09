//! Signed policy bundles for distribution

use hush_core::canonical::canonicalize;
use hush_core::{sha256, Hash, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy::Policy;

pub const POLICY_BUNDLE_SCHEMA_VERSION: &str = "clawdstrike-policy-bundle-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    /// Bundle schema version
    pub version: String,
    /// Unique bundle identifier
    pub bundle_id: String,
    /// ISO-8601 timestamp
    pub compiled_at: String,
    /// The compiled policy (after `extends` resolution / overlay merge).
    pub policy: Policy,
    /// SHA-256 of the canonicalized policy JSON.
    pub policy_hash: Hash,
    /// Optional list of source inputs (paths, refs, etc).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Optional metadata (build info, environment, etc).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl PolicyBundle {
    pub fn new(policy: Policy) -> Result<Self> {
        Self::new_with_sources(policy, Vec::new())
    }

    pub fn new_with_sources(policy: Policy, sources: Vec<String>) -> Result<Self> {
        let policy_hash = hash_policy(&policy)?;
        Ok(Self {
            version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: uuid::Uuid::new_v4().to_string(),
            compiled_at: chrono::Utc::now().to_rfc3339(),
            policy,
            policy_hash,
            sources,
            metadata: None,
        })
    }

    pub fn validate_version(&self) -> Result<()> {
        if self.version != POLICY_BUNDLE_SCHEMA_VERSION {
            return Err(Error::ConfigError(format!(
                "Unsupported policy bundle version: {} (expected {})",
                self.version, POLICY_BUNDLE_SCHEMA_VERSION
            )));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String> {
        self.validate_version()?;
        let value = serde_json::to_value(self)?;
        Ok(canonicalize(&value)?)
    }

    pub fn hash_sha256(&self) -> Result<Hash> {
        let canonical = self.to_canonical_json()?;
        Ok(sha256(canonical.as_bytes()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundle {
    pub bundle: PolicyBundle,
    pub signature: Signature,
    /// Optional embedded signer key (useful for distribution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

impl SignedPolicyBundle {
    pub fn sign(bundle: PolicyBundle, keypair: &Keypair) -> Result<Self> {
        bundle.validate_version()?;
        let canonical = bundle.to_canonical_json()?;
        let signature = keypair.sign(canonical.as_bytes());
        Ok(Self {
            bundle,
            signature,
            public_key: None,
        })
    }

    pub fn sign_with_public_key(bundle: PolicyBundle, keypair: &Keypair) -> Result<Self> {
        let mut signed = Self::sign(bundle, keypair)?;
        signed.public_key = Some(keypair.public_key());
        Ok(signed)
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result<bool> {
        self.bundle.validate_version()?;
        let canonical = self.bundle.to_canonical_json()?;
        Ok(public_key.verify(canonical.as_bytes(), &self.signature))
    }

    pub fn verify_embedded(&self) -> Result<bool> {
        match &self.public_key {
            Some(pk) => self.verify(pk),
            None => Err(Error::ConfigError(
                "No public_key embedded in bundle".to_string(),
            )),
        }
    }
}

fn hash_policy(policy: &Policy) -> Result<Hash> {
    let value = serde_json::to_value(policy)?;
    let canonical = canonicalize(&value)?;
    Ok(sha256(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_hash_is_stable_for_equivalent_policies() {
        let policy_a = Policy::default();
        let policy_b = Policy::default();
        let ha = hash_policy(&policy_a).unwrap();
        let hb = hash_policy(&policy_b).unwrap();
        assert_eq!(ha, hb);
    }

    #[test]
    fn signed_bundle_round_trip_verifies() {
        let keypair = Keypair::generate();
        let bundle = PolicyBundle::new(Policy::default()).unwrap();
        let signed = SignedPolicyBundle::sign_with_public_key(bundle, &keypair).unwrap();
        assert!(signed.verify_embedded().unwrap());
    }
}
