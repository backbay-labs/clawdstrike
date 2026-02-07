//! Trust bundles for mesh-grade verification.
//!
//! Adapted from `aegisnet::trust`, using [`hush_core`] for crypto.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

fn default_witness_quorum() -> usize {
    1
}

/// Trust bundle for "mesh-grade" verification.
///
/// When a list is non-empty, values must be present in that list (explicit
/// allowlist). When a list is empty, the bundle does not constrain that
/// dimension (MVP / dev mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    /// Optional schema tag for forwards compatibility (not enforced today).
    #[serde(default)]
    pub schema: Option<String>,

    /// Allowed log IDs (checkpoint operator node IDs).
    #[serde(default)]
    pub allowed_log_ids: Vec<String>,

    /// Allowed witness node IDs for checkpoint co-signing.
    #[serde(default)]
    pub allowed_witness_node_ids: Vec<String>,

    /// Allowed run receipt signer node IDs.
    #[serde(default)]
    pub allowed_receipt_signer_node_ids: Vec<String>,

    /// Allowed kernel-loader signer node IDs for per-run enforcement templates.
    #[serde(default)]
    pub allowed_kernel_loader_signer_node_ids: Vec<String>,

    /// Required run receipt enforcement tiers (reject best-effort receipts).
    #[serde(default)]
    pub required_receipt_enforcement_tiers: Vec<String>,

    /// Require kernel-loader signatures on kernel enforcement payloads.
    #[serde(default)]
    pub require_kernel_loader_signatures: bool,

    /// Required number of *distinct* allowed witness signatures on a checkpoint.
    #[serde(default = "default_witness_quorum")]
    pub witness_quorum: usize,
}

impl TrustBundle {
    /// Load a trust bundle from a JSON file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(&path).map_err(|e| {
            Error::Io(format!(
                "failed to read trust bundle {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;
        let bundle: Self =
            serde_json::from_slice(&bytes).map_err(|e| Error::Json(e.to_string()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate internal consistency.
    pub fn validate(&self) -> Result<()> {
        if self.witness_quorum == 0 {
            return Err(Error::InvalidTrustBundle(
                "witness_quorum must be >= 1".into(),
            ));
        }

        if self.witness_quorum > 1 && self.allowed_witness_node_ids.is_empty() {
            return Err(Error::InvalidTrustBundle(
                "witness_quorum > 1 requires allowed_witness_node_ids".into(),
            ));
        }

        if !self.allowed_witness_node_ids.is_empty()
            && self.witness_quorum > self.allowed_witness_node_ids.len()
        {
            return Err(Error::InvalidTrustBundle(format!(
                "witness_quorum ({}) exceeds allowed_witness_node_ids ({})",
                self.witness_quorum,
                self.allowed_witness_node_ids.len()
            )));
        }

        if self.require_kernel_loader_signatures
            && self.allowed_kernel_loader_signer_node_ids.is_empty()
        {
            return Err(Error::InvalidTrustBundle(
                "require_kernel_loader_signatures requires allowed_kernel_loader_signer_node_ids"
                    .into(),
            ));
        }

        Ok(())
    }

    /// Check if a log ID is allowed.
    pub fn log_id_allowed(&self, log_id: &str) -> bool {
        self.allowed_log_ids.is_empty() || self.allowed_log_ids.iter().any(|v| v == log_id)
    }

    /// Check if a witness node ID is allowed.
    pub fn witness_allowed(&self, witness_node_id: &str) -> bool {
        self.allowed_witness_node_ids.is_empty()
            || self
                .allowed_witness_node_ids
                .iter()
                .any(|v| v == witness_node_id)
    }

    /// Check if a receipt signer node ID is allowed.
    pub fn receipt_signer_allowed(&self, signer_node_id: &str) -> bool {
        self.allowed_receipt_signer_node_ids.is_empty()
            || self
                .allowed_receipt_signer_node_ids
                .iter()
                .any(|v| v == signer_node_id)
    }

    /// Check if a kernel-loader signer node ID is allowed.
    pub fn kernel_loader_signer_allowed(&self, signer_node_id: &str) -> bool {
        self.allowed_kernel_loader_signer_node_ids.is_empty()
            || self
                .allowed_kernel_loader_signer_node_ids
                .iter()
                .any(|v| v == signer_node_id)
    }

    /// Check if a receipt enforcement tier is acceptable.
    pub fn receipt_enforcement_tier_allowed(&self, tier: &str) -> bool {
        self.required_receipt_enforcement_tiers.is_empty()
            || self
                .required_receipt_enforcement_tiers
                .iter()
                .any(|v| v == tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_bundle() -> TrustBundle {
        TrustBundle {
            schema: None,
            allowed_log_ids: vec![],
            allowed_witness_node_ids: vec![],
            allowed_receipt_signer_node_ids: vec![],
            allowed_kernel_loader_signer_node_ids: vec![],
            required_receipt_enforcement_tiers: vec![],
            require_kernel_loader_signatures: false,
            witness_quorum: 1,
        }
    }

    #[test]
    fn dev_bundle_allows_everything() {
        let b = dev_bundle();
        b.validate().unwrap();
        assert!(b.log_id_allowed("any-log"));
        assert!(b.witness_allowed("any-witness"));
        assert!(b.receipt_signer_allowed("any-signer"));
        assert!(b.receipt_enforcement_tier_allowed("any-tier"));
    }

    #[test]
    fn allowlist_restricts() {
        let b = TrustBundle {
            allowed_log_ids: vec!["log-a".into()],
            ..dev_bundle()
        };
        assert!(b.log_id_allowed("log-a"));
        assert!(!b.log_id_allowed("log-b"));
    }

    #[test]
    fn quorum_zero_rejected() {
        let b = TrustBundle {
            witness_quorum: 0,
            ..dev_bundle()
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn quorum_exceeding_pool_rejected() {
        let b = TrustBundle {
            witness_quorum: 3,
            allowed_witness_node_ids: vec!["w1".into(), "w2".into()],
            ..dev_bundle()
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn quorum_gt1_without_allowlist_rejected() {
        let b = TrustBundle {
            witness_quorum: 2,
            ..dev_bundle()
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn kernel_loader_sig_without_allowlist_rejected() {
        let b = TrustBundle {
            require_kernel_loader_signatures: true,
            ..dev_bundle()
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let b = TrustBundle {
            schema: Some("spine.trust.v1".into()),
            allowed_log_ids: vec!["log-1".into()],
            allowed_witness_node_ids: vec!["w-1".into(), "w-2".into()],
            witness_quorum: 2,
            ..dev_bundle()
        };
        b.validate().unwrap();
        let json = serde_json::to_string_pretty(&b).unwrap();
        let restored: TrustBundle = serde_json::from_str(&json).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.allowed_log_ids, b.allowed_log_ids);
        assert_eq!(restored.witness_quorum, 2);
    }
}
