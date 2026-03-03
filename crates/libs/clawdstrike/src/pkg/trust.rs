//! Trust level computation and enforcement for packages.
//!
//! Trust levels form a monotonically increasing chain:
//!   Unverified < Signed < Verified < Certified
//!
//! Each level adds an additional cryptographic guarantee on top of the previous
//! one, enabling clients to gate installs on a minimum trust threshold.

use std::fmt;

use hush_core::MerkleProof;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors during trust level operations.
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("trust requirement not met: need {required}, got {actual}")]
    InsufficientTrust {
        required: TrustLevel,
        actual: TrustLevel,
    },
}

/// The trust level of a published package version.
///
/// Each successive variant represents strictly more cryptographic evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// No valid publisher signature present.
    Unverified = 0,
    /// Valid Ed25519 signature from the publisher.
    Signed = 1,
    /// Publisher signature plus registry counter-signature.
    Verified = 2,
    /// All of the above plus a Merkle inclusion proof in the transparency log.
    Certified = 3,
}

impl TrustLevel {
    /// Numeric rank (useful for comparisons without relying on `Ord` internals).
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// ANSI color code for CLI display.
    fn ansi_color(self) -> &'static str {
        match self {
            TrustLevel::Unverified => "\x1b[31m", // red
            TrustLevel::Signed => "\x1b[33m",     // yellow
            TrustLevel::Verified => "\x1b[32m",   // green
            TrustLevel::Certified => "\x1b[92m",  // bright green
        }
    }

    /// Display the trust level with ANSI colors for terminal output.
    pub fn colored(&self) -> String {
        format!("{}{}\x1b[0m", self.ansi_color(), self)
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            TrustLevel::Unverified => "unverified",
            TrustLevel::Signed => "signed",
            TrustLevel::Verified => "verified",
            TrustLevel::Certified => "certified",
        };
        write!(f, "{label}")
    }
}

/// Minimum trust level required for an operation (e.g., install).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustRequirement {
    /// Accept any package, even unsigned.
    None,
    /// Require at least a publisher signature.
    Signed,
    /// Require publisher + registry counter-signature.
    Verified,
    /// Require full transparency-log inclusion.
    Certified,
}

impl TrustRequirement {
    /// The minimum `TrustLevel` that satisfies this requirement.
    pub fn minimum_level(self) -> TrustLevel {
        match self {
            TrustRequirement::None => TrustLevel::Unverified,
            TrustRequirement::Signed => TrustLevel::Signed,
            TrustRequirement::Verified => TrustLevel::Verified,
            TrustRequirement::Certified => TrustLevel::Certified,
        }
    }
}

impl fmt::Display for TrustRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            TrustRequirement::None => "none",
            TrustRequirement::Signed => "signed",
            TrustRequirement::Verified => "verified",
            TrustRequirement::Certified => "certified",
        };
        write!(f, "{label}")
    }
}

/// Compute the trust level given available cryptographic evidence.
///
/// - `publisher_sig`: hex-encoded publisher Ed25519 signature (if present).
/// - `registry_sig`: hex-encoded registry counter-signature (if present).
/// - `merkle_proof`: a Merkle inclusion proof in the transparency log (if present).
///
/// The computation is additive: each layer must have the previous layer present.
pub fn compute_trust_level(
    publisher_sig: Option<&str>,
    registry_sig: Option<&str>,
    merkle_proof: Option<&MerkleProof>,
) -> TrustLevel {
    match (publisher_sig, registry_sig, merkle_proof) {
        (Some(_), Some(_), Some(_)) => TrustLevel::Certified,
        (Some(_), Some(_), None) => TrustLevel::Verified,
        (Some(_), _, _) => TrustLevel::Signed,
        _ => TrustLevel::Unverified,
    }
}

/// Check that `actual` trust level meets the given `required` threshold.
///
/// Returns `Ok(())` if satisfied, or a `TrustError::InsufficientTrust` with
/// the expected vs. actual levels.
pub fn check_trust(actual: TrustLevel, required: TrustRequirement) -> Result<(), TrustError> {
    let min = required.minimum_level();
    if actual >= min {
        Ok(())
    } else {
        Err(TrustError::InsufficientTrust {
            required: min,
            actual,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Hash;

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Unverified < TrustLevel::Signed);
        assert!(TrustLevel::Signed < TrustLevel::Verified);
        assert!(TrustLevel::Verified < TrustLevel::Certified);
    }

    #[test]
    fn compute_unverified() {
        let level = compute_trust_level(None, None, None);
        assert_eq!(level, TrustLevel::Unverified);
    }

    #[test]
    fn compute_signed() {
        let level = compute_trust_level(Some("abc123"), None, None);
        assert_eq!(level, TrustLevel::Signed);
    }

    #[test]
    fn compute_verified() {
        let level = compute_trust_level(Some("abc123"), Some("def456"), None);
        assert_eq!(level, TrustLevel::Verified);
    }

    #[test]
    fn compute_certified() {
        let proof = MerkleProof {
            tree_size: 4,
            leaf_index: 1,
            audit_path: vec![Hash::zero()],
        };
        let level = compute_trust_level(Some("abc123"), Some("def456"), Some(&proof));
        assert_eq!(level, TrustLevel::Certified);
    }

    #[test]
    fn compute_registry_sig_without_publisher_sig_is_unverified() {
        // Registry sig alone (no publisher sig) should not grant trust.
        let level = compute_trust_level(None, Some("def456"), None);
        assert_eq!(level, TrustLevel::Unverified);
    }

    #[test]
    fn compute_merkle_proof_without_registry_sig_is_signed() {
        // Merkle proof without registry sig caps at Signed.
        let proof = MerkleProof {
            tree_size: 4,
            leaf_index: 1,
            audit_path: vec![Hash::zero()],
        };
        let level = compute_trust_level(Some("abc123"), None, Some(&proof));
        assert_eq!(level, TrustLevel::Signed);
    }

    #[test]
    fn check_trust_passes_when_met() {
        assert!(check_trust(TrustLevel::Certified, TrustRequirement::Verified).is_ok());
        assert!(check_trust(TrustLevel::Verified, TrustRequirement::Verified).is_ok());
        assert!(check_trust(TrustLevel::Signed, TrustRequirement::Signed).is_ok());
        assert!(check_trust(TrustLevel::Unverified, TrustRequirement::None).is_ok());
    }

    #[test]
    fn check_trust_fails_when_insufficient() {
        let err = check_trust(TrustLevel::Signed, TrustRequirement::Verified).unwrap_err();
        match err {
            TrustError::InsufficientTrust { required, actual } => {
                assert_eq!(required, TrustLevel::Verified);
                assert_eq!(actual, TrustLevel::Signed);
            }
        }
    }

    #[test]
    fn check_trust_unverified_rejected_by_signed_requirement() {
        assert!(check_trust(TrustLevel::Unverified, TrustRequirement::Signed).is_err());
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(TrustLevel::Unverified.to_string(), "unverified");
        assert_eq!(TrustLevel::Signed.to_string(), "signed");
        assert_eq!(TrustLevel::Verified.to_string(), "verified");
        assert_eq!(TrustLevel::Certified.to_string(), "certified");
    }

    #[test]
    fn trust_level_rank() {
        assert_eq!(TrustLevel::Unverified.rank(), 0);
        assert_eq!(TrustLevel::Signed.rank(), 1);
        assert_eq!(TrustLevel::Verified.rank(), 2);
        assert_eq!(TrustLevel::Certified.rank(), 3);
    }

    #[test]
    fn trust_level_colored_output() {
        let output = TrustLevel::Unverified.colored();
        assert!(output.contains("unverified"));
        assert!(output.contains("\x1b[31m")); // red
        assert!(output.contains("\x1b[0m")); // reset
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        let level = TrustLevel::Certified;
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, "\"certified\"");
        let restored: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, level);
    }

    #[test]
    fn trust_requirement_serde_roundtrip() {
        let req = TrustRequirement::Verified;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "\"verified\"");
        let restored: TrustRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);
    }
}
