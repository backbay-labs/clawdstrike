//! Proof receipts and verification results
//!
//! This module defines the types for proof results, including:
//! - `ProofReceipt`: Certificate of a valid proof
//! - `ProofStep`: Individual derivation step
//! - `Counterexample`: Semantic model showing invalidity

use crate::formula::Formula;
use crate::operators::{AxiomSchema, InferenceRule};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of attempting to prove a formula
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofResult {
    /// Formula is a theorem (valid in all models)
    Valid(ProofReceipt),

    /// Formula is invalid (counterexample exists)
    Invalid(Counterexample),

    /// Proof attempt was inconclusive
    Unknown { reason: String },

    /// Proof timed out
    Timeout { elapsed_ms: u64 },
}

impl ProofResult {
    /// Check if the result indicates validity
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    /// Check if the result indicates invalidity
    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }

    /// Get the proof receipt if valid
    pub fn receipt(&self) -> Option<&ProofReceipt> {
        match self {
            Self::Valid(r) => Some(r),
            _ => None,
        }
    }

    /// Get the counterexample if invalid
    pub fn counterexample(&self) -> Option<&Counterexample> {
        match self {
            Self::Invalid(c) => Some(c),
            _ => None,
        }
    }
}

/// Certificate that a formula has been proven
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofReceipt {
    /// Unique identifier for this proof
    pub proof_id: String,

    /// The formula that was proven
    pub formula: Formula,

    /// Hash of the formula (for verification)
    pub formula_hash: String,

    /// Sequence of proof steps
    pub steps: Vec<ProofStep>,

    /// Total number of steps in the proof
    pub step_count: usize,

    /// Maximum nesting depth of the proof
    pub max_depth: usize,

    /// LEAN proof term (if available)
    pub lean_proof: Option<String>,

    /// Whether Z3 also validated the formula
    pub z3_valid: bool,

    /// When the proof was generated
    pub generated_at: DateTime<Utc>,

    /// How long the proof took (milliseconds)
    pub proof_time_ms: u64,
}

impl ProofReceipt {
    /// Create a new proof receipt
    pub fn new(formula: Formula, steps: Vec<ProofStep>) -> Self {
        let formula_hash = crate::formula_hash(&formula);
        let step_count = steps.len();
        let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);

        Self {
            proof_id: format!("proof_{}", &formula_hash[..12]),
            formula,
            formula_hash,
            steps,
            step_count,
            max_depth,
            lean_proof: None,
            z3_valid: false,
            generated_at: Utc::now(),
            proof_time_ms: 0,
        }
    }

    /// Add LEAN proof term
    pub fn with_lean_proof(mut self, lean_proof: String) -> Self {
        self.lean_proof = Some(lean_proof);
        self
    }

    /// Mark as Z3 validated
    pub fn with_z3_valid(mut self, valid: bool) -> Self {
        self.z3_valid = valid;
        self
    }

    /// Set proof time
    pub fn with_proof_time(mut self, ms: u64) -> Self {
        self.proof_time_ms = ms;
        self
    }
}

/// A single step in a proof derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// Step number (1-indexed)
    pub step_num: usize,

    /// Nesting depth in the proof tree
    pub depth: usize,

    /// The formula derived in this step
    pub formula: Formula,

    /// The rule or axiom used
    pub justification: Justification,

    /// References to previous steps used
    pub premises: Vec<usize>,

    /// Human-readable explanation
    pub explanation: Option<String>,
}

/// Justification for a proof step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Justification {
    /// An axiom instance
    Axiom(AxiomSchema),

    /// An inference rule application
    Rule(InferenceRule),

    /// A hypothesis (in a subproof)
    Hypothesis,

    /// A definition expansion
    Definition(String),

    /// A previously proven theorem
    Theorem(String),
}

/// A counterexample showing a formula is invalid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterexample {
    /// The formula that was invalidated
    pub formula: Formula,

    /// Description of the countermodel
    pub model_description: String,

    /// State assignments (atom -> value)
    pub state_assignments: Vec<StateAssignment>,

    /// World structure (for modal formulas)
    pub worlds: Option<WorldStructure>,

    /// Time structure (for temporal formulas)
    pub times: Option<TimeStructure>,

    /// Evaluation trace showing why formula is false
    pub evaluation_trace: Vec<EvaluationStep>,

    /// When the counterexample was generated
    pub generated_at: DateTime<Utc>,
}

impl Counterexample {
    /// Create a simple counterexample for propositional formulas
    pub fn simple(formula: Formula, assignments: Vec<StateAssignment>) -> Self {
        Self {
            formula,
            model_description: "Propositional countermodel".to_string(),
            state_assignments: assignments,
            worlds: None,
            times: None,
            evaluation_trace: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    /// Create a modal counterexample
    pub fn modal(
        formula: Formula,
        assignments: Vec<StateAssignment>,
        worlds: WorldStructure,
    ) -> Self {
        Self {
            formula,
            model_description: "Modal countermodel (S5)".to_string(),
            state_assignments: assignments,
            worlds: Some(worlds),
            times: None,
            evaluation_trace: Vec::new(),
            generated_at: Utc::now(),
        }
    }

    /// Create a temporal counterexample
    pub fn temporal(
        formula: Formula,
        assignments: Vec<StateAssignment>,
        times: TimeStructure,
    ) -> Self {
        Self {
            formula,
            model_description: "Temporal countermodel".to_string(),
            state_assignments: assignments,
            worlds: None,
            times: Some(times),
            evaluation_trace: Vec::new(),
            generated_at: Utc::now(),
        }
    }
}

/// Assignment of truth value to an atom at a world/time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAssignment {
    /// The atomic proposition
    pub atom: String,

    /// The world (if modal)
    pub world: Option<String>,

    /// The time (if temporal)
    pub time: Option<i64>,

    /// The truth value
    pub value: bool,
}

/// World structure for modal counterexamples
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldStructure {
    /// List of worlds
    pub worlds: Vec<String>,

    /// Accessibility relation (pairs of accessible worlds)
    pub accessibility: Vec<(String, String)>,

    /// The actual world
    pub actual_world: String,
}

/// Time structure for temporal counterexamples
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStructure {
    /// Discrete time points
    pub times: Vec<i64>,

    /// The current time
    pub now: i64,

    /// Precedence relation (optional, for branching time)
    pub precedence: Option<Vec<(i64, i64)>>,
}

/// Step in the evaluation of a formula (for tracing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationStep {
    /// The subformula being evaluated
    pub subformula: String,

    /// The world/time context
    pub context: String,

    /// The resulting value
    pub result: bool,

    /// Explanation
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_receipt_creation() {
        let formula = Formula::implies(Formula::atom("p"), Formula::atom("p"));

        let steps = vec![ProofStep {
            step_num: 1,
            depth: 0,
            formula: formula.clone(),
            justification: Justification::Axiom(AxiomSchema::ModalT),
            premises: vec![],
            explanation: Some("Identity is a tautology".to_string()),
        }];

        let receipt = ProofReceipt::new(formula, steps);

        assert_eq!(receipt.step_count, 1);
        assert!(receipt.proof_id.starts_with("proof_"));
    }

    #[test]
    fn test_counterexample_simple() {
        let formula = Formula::and(Formula::atom("p"), Formula::not(Formula::atom("p")));

        let assignments = vec![StateAssignment {
            atom: "p".to_string(),
            world: None,
            time: None,
            value: true,
        }];

        let cex = Counterexample::simple(formula, assignments);

        assert_eq!(cex.state_assignments.len(), 1);
    }

    #[test]
    fn test_proof_result_methods() {
        let formula = Formula::atom("p");
        let receipt = ProofReceipt::new(formula.clone(), vec![]);

        let valid = ProofResult::Valid(receipt);
        assert!(valid.is_valid());
        assert!(valid.receipt().is_some());

        let invalid = ProofResult::Invalid(Counterexample::simple(formula, vec![]));
        assert!(invalid.is_invalid());
        assert!(invalid.counterexample().is_some());
    }

    #[test]
    fn test_serialization() {
        let formula = Formula::necessity(Formula::atom("p"));
        let receipt = ProofReceipt::new(formula, vec![]);

        let json = match serde_json::to_string(&receipt) {
            Ok(json) => json,
            Err(err) => panic!("failed to serialize proof receipt: {err}"),
        };
        let recovered: ProofReceipt = match serde_json::from_str(&json) {
            Ok(recovered) => recovered,
            Err(err) => panic!("failed to deserialize proof receipt: {err}"),
        };

        assert_eq!(receipt.proof_id, recovered.proof_id);
    }
}
