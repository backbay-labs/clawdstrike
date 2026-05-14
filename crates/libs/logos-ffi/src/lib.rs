//! # logos-ffi
//!
//! FFI bindings to the Logos formal reasoning system.
//!
//! Logos is a formal "Language of Thought" implementing modal-temporal logic
//! with extensions for explanatory, epistemic, and normative reasoning.
//!
//! ## Operator Layers
//!
//! - **Layer 0 (Core TM)**: Boolean + Modal (□, ◇) + Temporal (G, F, H, P)
//! - **Layer 1 (Explanatory)**: Counterfactual (□→, ◇→), Grounding (≤), Causal (○→)
//! - **Layer 2 (Epistemic)**: Belief (B), Probability (Pr), Epistemic modals
//! - **Layer 3 (Normative)**: Obligation (O), Permission (P), Preference (≺)
//!
//! ## Example
//!
//! ```rust
//! use logos_ffi::*;
//!
//! // Build a formula: □(p → q) → (□p → □q)  (Modal K axiom)
//! let p = Formula::atom("p");
//! let q = Formula::atom("q");
//! let formula = Formula::implies(
//!     Formula::necessity(Formula::implies(p.clone(), q.clone())),
//!     Formula::implies(Formula::necessity(p), Formula::necessity(q)),
//! );
//!
//! // Check if it's a theorem (requires LEAN runtime)
//! // let result = check_proof(&formula)?;
//! ```

pub mod formula;
pub mod operators;
pub mod proof;
pub mod routing;

pub use formula::*;
pub use operators::*;
pub use proof::*;
pub use routing::*;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during proof checking
#[derive(Debug, Error)]
pub enum LogosError {
    #[error("LEAN runtime not available (enable 'lean-runtime' feature)")]
    LeanNotAvailable,

    #[error("Formula construction error: {0}")]
    FormulaError(String),

    #[error("Proof failed: {0}")]
    ProofFailed(String),

    #[error("Type mismatch in formula: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    #[error("Invalid agent identifier: {0}")]
    InvalidAgent(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LogosError>;

/// Compute deterministic hash for a formula
pub fn formula_hash(formula: &Formula) -> String {
    let json = serde_json::to_string(formula).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Logos context for proof checking
///
/// This manages the connection to the LEAN 4 runtime (when available)
/// or operates in simulation mode for testing.
#[derive(Debug)]
pub struct LogosContext {
    /// Whether LEAN runtime is available
    lean_available: bool,
    /// Cache of verified formulas (hash -> ProofReceipt)
    proof_cache: std::collections::HashMap<String, ProofReceipt>,
}

impl Default for LogosContext {
    fn default() -> Self {
        Self::new()
    }
}

impl LogosContext {
    /// Create a new Logos context
    pub fn new() -> Self {
        Self {
            lean_available: cfg!(feature = "lean-runtime"),
            proof_cache: std::collections::HashMap::new(),
        }
    }

    /// Check if LEAN runtime is available
    pub fn lean_available(&self) -> bool {
        self.lean_available
    }

    /// Attempt to prove a formula
    pub fn check_proof(&mut self, formula: &Formula) -> Result<ProofResult> {
        let hash = formula_hash(formula);

        // Check cache first
        if let Some(receipt) = self.proof_cache.get(&hash) {
            return Ok(ProofResult::Valid(receipt.clone()));
        }

        // Without LEAN runtime, we can only validate syntactic structure
        if !self.lean_available {
            // Return "unknown" - semantically valid but not proven
            return Ok(ProofResult::Unknown {
                reason: "LEAN runtime not available".to_string(),
            });
        }

        // TODO: Call LEAN 4 runtime via FFI
        // For now, return unknown
        Ok(ProofResult::Unknown {
            reason: "LEAN FFI not yet implemented".to_string(),
        })
    }

    /// Clear the proof cache
    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = LogosContext::new();
        // LEAN runtime only available with feature flag
        assert!(!ctx.lean_available() || cfg!(feature = "lean-runtime"));
    }

    #[test]
    fn test_formula_hash_deterministic() {
        let p = Formula::atom("p");
        let q = Formula::atom("q");
        let f1 = Formula::and(p.clone(), q.clone());
        let f2 = Formula::and(p, q);

        assert_eq!(formula_hash(&f1), formula_hash(&f2));
    }

    #[test]
    fn test_formula_construction() {
        // Modal K axiom: □(p → q) → (□p → □q)
        let p = Formula::atom("p");
        let q = Formula::atom("q");

        let k_axiom = Formula::implies(
            Formula::necessity(Formula::implies(p.clone(), q.clone())),
            Formula::implies(Formula::necessity(p), Formula::necessity(q)),
        );

        // Should be constructable without errors
        assert!(matches!(k_axiom, Formula::Implies(_, _)));
    }
}
