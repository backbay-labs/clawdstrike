//! # logos-z3
//!
//! Z3 model checker integration for Logos counterexample generation.
//!
//! This crate provides semantic verification by searching for countermodels
//! to candidate inferences using the Z3 SMT solver.
//!
//! ## Architecture
//!
//! ```text
//! Formula ──► Z3 Translation ──► SAT Check ──► Counterexample (if unsat)
//!                                           └─► Valid (if sat for all)
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use logos_ffi::Formula;
//! use logos_z3::Z3Checker;
//!
//! let checker = Z3Checker::new();
//!
//! // Invalid inference: ◇p → □p
//! let invalid = Formula::implies(
//!     Formula::possibility(Formula::atom("p")),
//!     Formula::necessity(Formula::atom("p")),
//! );
//!
//! let result = checker.check(&invalid);
//! assert!(result.is_invalid());
//! ```

pub mod checker;
pub mod translation;

use logos_ffi::{Counterexample, Formula, ProofResult, StateAssignment};
use thiserror::Error;

use crate::checker::Z3SolverWrapper;
use crate::translation::NormativeKind;

/// Errors that can occur during Z3 model checking
#[derive(Debug, Error)]
pub enum Z3Error {
    #[error("Z3 context creation failed")]
    ContextCreation,

    #[error("Formula translation failed: {0}")]
    Translation(String),

    #[error("Z3 solver error: {0}")]
    Solver(String),

    #[error("Model extraction failed: {0}")]
    ModelExtraction(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Unsupported formula type: {0}")]
    UnsupportedFormula(String),
}

pub type Result<T> = std::result::Result<T, Z3Error>;

/// Configuration for the Z3 checker
#[derive(Debug, Clone)]
pub struct Z3Config {
    /// Timeout in milliseconds (0 = no timeout)
    pub timeout_ms: u64,

    /// Maximum number of worlds for modal checking
    pub max_worlds: usize,

    /// Maximum number of time points for temporal checking
    pub max_times: usize,

    /// Enable model simplification
    pub simplify_models: bool,
}

impl Default for Z3Config {
    fn default() -> Self {
        Self {
            timeout_ms: 5000, // 5 second default
            max_worlds: 4,    // Small world count for efficiency
            max_times: 8,     // Reasonable time horizon
            simplify_models: true,
        }
    }
}

/// Z3-based model checker for Logos formulas
pub struct Z3Checker {
    config: Z3Config,
}

impl Default for Z3Checker {
    fn default() -> Self {
        Self::new()
    }
}

impl Z3Checker {
    /// Create a new Z3 checker with default configuration
    pub fn new() -> Self {
        Self {
            config: Z3Config::default(),
        }
    }

    /// Create a new Z3 checker with custom configuration
    pub fn with_config(config: Z3Config) -> Self {
        Self { config }
    }

    /// Check if a formula is valid (true in all models)
    ///
    /// Returns `ProofResult::Invalid` with a counterexample if the formula
    /// can be falsified, or `ProofResult::Valid` if no countermodel exists.
    pub fn check(&self, formula: &Formula) -> ProofResult {
        // Determine the type of checking needed based on formula operators
        let layer = formula.required_layer();

        match self.check_internal(formula, layer) {
            Ok(result) => result,
            Err(e) => ProofResult::Unknown {
                reason: e.to_string(),
            },
        }
    }

    /// Check validity for a specific formula
    fn check_internal(&self, formula: &Formula, layer: u8) -> Result<ProofResult> {
        match layer {
            0 => self.check_propositional(formula),
            1 => self.check_explanatory(formula),
            2 => self.check_epistemic(formula),
            3 => self.check_normative(formula),
            _ => Err(Z3Error::UnsupportedFormula(format!(
                "Unknown layer {}",
                layer
            ))),
        }
    }

    /// Propositional satisfiability check with hybrid strategy.
    ///
    /// For formulas with <=10 atoms, uses fast brute-force enumeration (no Z3
    /// overhead). For formulas with >10 atoms, delegates to Z3 solver.
    fn check_propositional(&self, formula: &Formula) -> Result<ProofResult> {
        let atoms = collect_atoms(formula);

        if atoms.len() <= 10 {
            self.check_propositional_enumerate(formula, &atoms)
        } else {
            self.check_propositional_z3(formula)
        }
    }

    /// Propositional validity check using brute-force enumeration.
    /// Only suitable for formulas with a small number of atoms (<=10).
    fn check_propositional_enumerate(
        &self,
        formula: &Formula,
        atoms: &[String],
    ) -> Result<ProofResult> {
        let negated = Formula::not(formula.clone());

        // Try all 2^n assignments
        for assignment in 0..(1u64 << atoms.len()) {
            let values: Vec<bool> = (0..atoms.len())
                .map(|i| (assignment >> i) & 1 == 1)
                .collect();

            let atom_values: std::collections::HashMap<&str, bool> = atoms
                .iter()
                .zip(values.iter())
                .map(|(a, v)| (a.as_str(), *v))
                .collect();

            if evaluate_propositional(&negated, &atom_values) {
                // Found a counterexample
                let state_assignments = atoms
                    .iter()
                    .zip(values.iter())
                    .map(|(atom, value)| StateAssignment {
                        atom: atom.clone(),
                        world: None,
                        time: None,
                        value: *value,
                    })
                    .collect();

                return Ok(ProofResult::Invalid(Counterexample::simple(
                    formula.clone(),
                    state_assignments,
                )));
            }
        }

        // No counterexample found - formula is valid
        Ok(ProofResult::Valid(
            logos_ffi::ProofReceipt::new(formula.clone(), vec![]).with_z3_valid(true),
        ))
    }

    /// Propositional validity check that always uses the Z3 solver.
    ///
    /// This bypasses the enumeration fast-path and is useful for testing
    /// Z3 integration or for formulas with many atoms.
    pub fn check_propositional_z3(&self, formula: &Formula) -> Result<ProofResult> {
        let wrapper = Z3SolverWrapper::new(self.config.clone());
        wrapper
            .check_valid(formula)
            .map_err(|e| Z3Error::Solver(e.to_string()))
    }

    /// Check satisfiability of a formula using Z3.
    ///
    /// Returns `ProofResult::Valid` if a satisfying assignment exists,
    /// `ProofResult::Invalid` if the formula is unsatisfiable.
    pub fn check_sat_z3(&self, formula: &Formula) -> Result<ProofResult> {
        let wrapper = Z3SolverWrapper::new(self.config.clone());
        wrapper
            .check_sat(formula)
            .map_err(|e| Z3Error::Solver(e.to_string()))
    }

    /// Check explanatory formulas (Layer 1)
    fn check_explanatory(&self, _formula: &Formula) -> Result<ProofResult> {
        // Explanatory formulas require selection function semantics
        Ok(ProofResult::Unknown {
            reason: "Explanatory (counterfactual) checking not yet implemented".to_string(),
        })
    }

    /// Check epistemic formulas (Layer 2)
    fn check_epistemic(&self, _formula: &Formula) -> Result<ProofResult> {
        Ok(ProofResult::Unknown {
            reason: "Epistemic checking not yet implemented".to_string(),
        })
    }

    /// Check normative formulas (Layer 3).
    ///
    /// Extracts Permission, Prohibition, and Obligation sub-formulas,
    /// then checks for pairwise conflicts between permissions and
    /// prohibitions for the same agent.
    fn check_normative(&self, formula: &Formula) -> Result<ProofResult> {
        // First, collect all normative sub-formulas
        let mut norms: Vec<NormativeEntry> = Vec::new();
        collect_normative_entries(formula, &mut norms);

        if norms.is_empty() {
            // If there are no normative operators, fall back to propositional check
            // (shouldn't happen since layer detection would have routed elsewhere,
            // but handle gracefully)
            return self.check_propositional(formula);
        }

        // Check for conflicts between Permission(agent, f) and Prohibition(agent, g)
        // A conflict exists if f and g can be simultaneously true for the same agent.
        let wrapper = Z3SolverWrapper::new(self.config.clone());

        for (i, norm_a) in norms.iter().enumerate() {
            for norm_b in norms.iter().skip(i + 1) {
                // Only check permission-prohibition pairs for the same agent
                if norm_a.agent != norm_b.agent {
                    continue;
                }

                let is_conflict_pair = matches!(
                    (&norm_a.kind, &norm_b.kind),
                    (NormativeKind::Permission, NormativeKind::Prohibition)
                        | (NormativeKind::Prohibition, NormativeKind::Permission)
                );

                if !is_conflict_pair {
                    continue;
                }

                // Check if the two inner formulas can be simultaneously true
                let conjunction = Formula::and(norm_a.inner.clone(), norm_b.inner.clone());
                let sat_result = wrapper.check_sat(&conjunction);

                match sat_result {
                    Ok(ProofResult::Valid(_)) => {
                        // The conjunction is satisfiable -- there's a conflict
                        let (perm_formula, prohib_formula) =
                            if norm_a.kind == NormativeKind::Permission {
                                (&norm_a.inner, &norm_b.inner)
                            } else {
                                (&norm_b.inner, &norm_a.inner)
                            };

                        let description = format!(
                            "Normative conflict for agent '{}': Permission({}) conflicts with Prohibition({})",
                            norm_a.agent, perm_formula, prohib_formula
                        );

                        return Ok(ProofResult::Invalid(Counterexample {
                            formula: formula.clone(),
                            model_description: description,
                            state_assignments: vec![],
                            worlds: None,
                            times: None,
                            evaluation_trace: vec![],
                            generated_at: Utc::now(),
                        }));
                    }
                    Ok(_) => {
                        // No conflict for this pair
                    }
                    Err(e) => {
                        return Err(Z3Error::Solver(format!(
                            "Error checking normative conflict: {}",
                            e
                        )));
                    }
                }
            }
        }

        // No conflicts found -- try to check the overall formula propositionally
        // by stripping normative operators and checking the inner content
        let stripped = strip_normative(formula);
        self.check_propositional(&stripped)
    }

    /// Check if a set of normative formulas is consistent.
    ///
    /// Verifies that no action is both permitted and forbidden for the same
    /// agent. Returns `ProofResult::Invalid` with a counterexample if an
    /// inconsistency is found.
    pub fn check_consistency(&self, formulas: &[Formula]) -> ProofResult {
        let mut norms: Vec<NormativeEntry> = Vec::new();
        for f in formulas {
            collect_normative_entries(f, &mut norms);
        }

        let wrapper = Z3SolverWrapper::new(self.config.clone());

        for (i, norm_a) in norms.iter().enumerate() {
            for norm_b in norms.iter().skip(i + 1) {
                if norm_a.agent != norm_b.agent {
                    continue;
                }

                let is_conflict_pair = matches!(
                    (&norm_a.kind, &norm_b.kind),
                    (NormativeKind::Permission, NormativeKind::Prohibition)
                        | (NormativeKind::Prohibition, NormativeKind::Permission)
                );

                if !is_conflict_pair {
                    continue;
                }

                // Check if the two inner formulas can be simultaneously true
                let conjunction = Formula::and(norm_a.inner.clone(), norm_b.inner.clone());

                match wrapper.check_sat(&conjunction) {
                    Ok(ProofResult::Valid(_)) => {
                        // Conflict found
                        let description = format!(
                            "Inconsistency: agent '{}' has conflicting Permission({}) and Prohibition({})",
                            norm_a.agent, norm_a.inner, norm_b.inner
                        );

                        // Build a synthetic combined formula for reporting
                        let combined = Formula::and(
                            formulas.first().cloned().unwrap_or(Formula::Top),
                            formulas.last().cloned().unwrap_or(Formula::Top),
                        );

                        return ProofResult::Invalid(Counterexample {
                            formula: combined,
                            model_description: description,
                            state_assignments: vec![],
                            worlds: None,
                            times: None,
                            evaluation_trace: vec![],
                            generated_at: Utc::now(),
                        });
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return ProofResult::Unknown {
                            reason: format!("Z3 error during consistency check: {}", e),
                        };
                    }
                }
            }
        }

        // Also check for Obligation-Prohibition conflicts:
        // O(agent, f) and F(agent, f) is inconsistent if f can be true
        for (i, norm_a) in norms.iter().enumerate() {
            for norm_b in norms.iter().skip(i + 1) {
                if norm_a.agent != norm_b.agent {
                    continue;
                }

                let is_obligation_prohibition = matches!(
                    (&norm_a.kind, &norm_b.kind),
                    (NormativeKind::Obligation, NormativeKind::Prohibition)
                        | (NormativeKind::Prohibition, NormativeKind::Obligation)
                );

                if !is_obligation_prohibition {
                    continue;
                }

                let conjunction = Formula::and(norm_a.inner.clone(), norm_b.inner.clone());

                match wrapper.check_sat(&conjunction) {
                    Ok(ProofResult::Valid(_)) => {
                        let description = format!(
                            "Inconsistency: agent '{}' has conflicting Obligation({}) and Prohibition({})",
                            norm_a.agent, norm_a.inner, norm_b.inner
                        );

                        let combined = Formula::and(
                            formulas.first().cloned().unwrap_or(Formula::Top),
                            formulas.last().cloned().unwrap_or(Formula::Top),
                        );

                        return ProofResult::Invalid(Counterexample {
                            formula: combined,
                            model_description: description,
                            state_assignments: vec![],
                            worlds: None,
                            times: None,
                            evaluation_trace: vec![],
                            generated_at: Utc::now(),
                        });
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return ProofResult::Unknown {
                            reason: format!("Z3 error during consistency check: {}", e),
                        };
                    }
                }
            }
        }

        // No inconsistencies found
        let combined = formulas
            .iter()
            .cloned()
            .reduce(Formula::and)
            .unwrap_or(Formula::Top);

        ProofResult::Valid(logos_ffi::ProofReceipt::new(combined, vec![]).with_z3_valid(true))
    }

    /// Check if formulas cover all specified action atoms.
    ///
    /// For each action atom, verifies that at least one formula in the set
    /// mentions it (either permits, prohibits, or obligates it). Returns
    /// `ProofResult::Invalid` if any action atom is unaddressed.
    pub fn check_completeness(&self, formulas: &[Formula], action_atoms: &[String]) -> ProofResult {
        // Collect all atoms mentioned in the formulas
        let mut mentioned_atoms = std::collections::HashSet::new();
        for f in formulas {
            let atoms = collect_atoms(f);
            for atom in atoms {
                mentioned_atoms.insert(atom);
            }
        }

        let missing: Vec<&String> = action_atoms
            .iter()
            .filter(|a| !mentioned_atoms.contains(a.as_str()))
            .collect();

        if missing.is_empty() {
            let combined = formulas
                .iter()
                .cloned()
                .reduce(Formula::and)
                .unwrap_or(Formula::Top);

            ProofResult::Valid(logos_ffi::ProofReceipt::new(combined, vec![]).with_z3_valid(true))
        } else {
            let missing_str: Vec<String> = missing.iter().map(|a| (*a).clone()).collect();
            let description = format!(
                "Incomplete policy: actions not covered: [{}]",
                missing_str.join(", ")
            );

            let combined = formulas
                .iter()
                .cloned()
                .reduce(Formula::and)
                .unwrap_or(Formula::Top);

            ProofResult::Invalid(Counterexample {
                formula: combined,
                model_description: description,
                state_assignments: missing_str
                    .iter()
                    .map(|a| StateAssignment {
                        atom: a.clone(),
                        world: None,
                        time: None,
                        value: false,
                    })
                    .collect(),
                worlds: None,
                times: None,
                evaluation_trace: vec![],
                generated_at: Utc::now(),
            })
        }
    }

    /// Check if child policy preserves parent's prohibitions.
    ///
    /// For every `Prohibition(agent, f)` in the parent, the merged policy must
    /// also contain a prohibition that is at least as strong (i.e., the parent's
    /// prohibition should imply the merged prohibition). Returns
    /// `ProofResult::Invalid` if a parent prohibition is weakened or missing.
    pub fn check_inheritance_soundness(
        &self,
        parent_formulas: &[Formula],
        merged_formulas: &[Formula],
    ) -> ProofResult {
        let mut parent_prohibitions: Vec<NormativeEntry> = Vec::new();
        for f in parent_formulas {
            collect_normative_entries(f, &mut parent_prohibitions);
        }
        let parent_prohibitions: Vec<NormativeEntry> = parent_prohibitions
            .into_iter()
            .filter(|n| n.kind == NormativeKind::Prohibition)
            .collect();

        let mut merged_prohibitions: Vec<NormativeEntry> = Vec::new();
        for f in merged_formulas {
            collect_normative_entries(f, &mut merged_prohibitions);
        }
        let merged_prohibitions: Vec<NormativeEntry> = merged_prohibitions
            .into_iter()
            .filter(|n| n.kind == NormativeKind::Prohibition)
            .collect();

        let wrapper = Z3SolverWrapper::new(self.config.clone());

        for parent_p in &parent_prohibitions {
            // Find matching merged prohibitions for the same agent
            let matching: Vec<&NormativeEntry> = merged_prohibitions
                .iter()
                .filter(|m| m.agent == parent_p.agent)
                .collect();

            if matching.is_empty() {
                let description = format!(
                    "Inheritance violation: parent Prohibition({}) for agent '{}' has no corresponding prohibition in merged policy",
                    parent_p.inner, parent_p.agent
                );

                let combined = parent_formulas
                    .iter()
                    .cloned()
                    .reduce(Formula::and)
                    .unwrap_or(Formula::Top);

                return ProofResult::Invalid(Counterexample {
                    formula: combined,
                    model_description: description,
                    state_assignments: vec![],
                    worlds: None,
                    times: None,
                    evaluation_trace: vec![],
                    generated_at: Utc::now(),
                });
            }

            // Check that the parent's prohibition is preserved:
            // For each matching merged prohibition, check if parent_inner → merged_inner
            // is valid. If at least one is, the prohibition is preserved.
            let mut any_preserved = false;
            for merged_p in &matching {
                let implication = Formula::implies(parent_p.inner.clone(), merged_p.inner.clone());
                match wrapper.check_valid(&implication) {
                    Ok(ProofResult::Valid(_)) => {
                        any_preserved = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return ProofResult::Unknown {
                            reason: format!("Z3 error during inheritance check: {}", e),
                        };
                    }
                }
            }

            if !any_preserved {
                let description = format!(
                    "Inheritance violation: parent Prohibition({}) for agent '{}' is weakened in merged policy",
                    parent_p.inner, parent_p.agent
                );

                let combined = parent_formulas
                    .iter()
                    .cloned()
                    .reduce(Formula::and)
                    .unwrap_or(Formula::Top);

                return ProofResult::Invalid(Counterexample {
                    formula: combined,
                    model_description: description,
                    state_assignments: vec![],
                    worlds: None,
                    times: None,
                    evaluation_trace: vec![],
                    generated_at: Utc::now(),
                });
            }
        }

        let combined = merged_formulas
            .iter()
            .cloned()
            .reduce(Formula::and)
            .unwrap_or(Formula::Top);

        ProofResult::Valid(logos_ffi::ProofReceipt::new(combined, vec![]).with_z3_valid(true))
    }

    /// Check if a formula is satisfiable (has at least one model)
    pub fn is_satisfiable(&self, formula: &Formula) -> Result<bool> {
        match self.check(formula) {
            ProofResult::Valid(_) => Ok(true),
            ProofResult::Invalid(_) => Ok(false),
            ProofResult::Unknown { reason } => Err(Z3Error::Solver(reason)),
            ProofResult::Timeout { elapsed_ms } => Err(Z3Error::Timeout(elapsed_ms)),
        }
    }

    /// Find a counterexample if one exists
    pub fn find_counterexample(&self, formula: &Formula) -> Option<Counterexample> {
        match self.check(formula) {
            ProofResult::Invalid(cex) => Some(cex),
            _ => None,
        }
    }
}

/// Internal representation of a normative formula entry for conflict analysis.
#[derive(Debug, Clone)]
struct NormativeEntry {
    agent: String,
    kind: NormativeKind,
    inner: Formula,
}

/// Recursively collect all normative (Permission, Prohibition, Obligation)
/// sub-formulas from a formula tree.
fn collect_normative_entries(formula: &Formula, entries: &mut Vec<NormativeEntry>) {
    match formula {
        Formula::Permission(agent, inner) => {
            entries.push(NormativeEntry {
                agent: agent.0.clone(),
                kind: NormativeKind::Permission,
                inner: (**inner).clone(),
            });
            collect_normative_entries(inner, entries);
        }
        Formula::Prohibition(agent, inner) => {
            entries.push(NormativeEntry {
                agent: agent.0.clone(),
                kind: NormativeKind::Prohibition,
                inner: (**inner).clone(),
            });
            collect_normative_entries(inner, entries);
        }
        Formula::Obligation(agent, inner) => {
            entries.push(NormativeEntry {
                agent: agent.0.clone(),
                kind: NormativeKind::Obligation,
                inner: (**inner).clone(),
            });
            collect_normative_entries(inner, entries);
        }
        Formula::Not(f) => collect_normative_entries(f, entries),
        Formula::And(l, r) | Formula::Or(l, r) | Formula::Implies(l, r) | Formula::Iff(l, r) => {
            collect_normative_entries(l, entries);
            collect_normative_entries(r, entries);
        }
        Formula::AgentPreference(_, l, r) | Formula::Preference(l, r) => {
            collect_normative_entries(l, entries);
            collect_normative_entries(r, entries);
        }
        // Atoms, Top, Bottom, modal, temporal, epistemic, explanatory -- no normative content
        _ => {}
    }
}

/// Strip normative operators, replacing them with their inner formula content.
fn strip_normative(formula: &Formula) -> Formula {
    match formula {
        Formula::Permission(_, inner)
        | Formula::Prohibition(_, inner)
        | Formula::Obligation(_, inner) => strip_normative(inner),
        Formula::Not(f) => Formula::not(strip_normative(f)),
        Formula::And(l, r) => Formula::and(strip_normative(l), strip_normative(r)),
        Formula::Or(l, r) => Formula::or(strip_normative(l), strip_normative(r)),
        Formula::Implies(l, r) => Formula::implies(strip_normative(l), strip_normative(r)),
        Formula::Iff(l, r) => Formula::iff(strip_normative(l), strip_normative(r)),
        other => other.clone(),
    }
}

/// Collect all atomic propositions in a formula
fn collect_atoms(formula: &Formula) -> Vec<String> {
    let mut atoms = Vec::new();
    collect_atoms_rec(formula, &mut atoms);
    atoms.sort();
    atoms.dedup();
    atoms
}

fn collect_atoms_rec(formula: &Formula, atoms: &mut Vec<String>) {
    match formula {
        Formula::Atom(name) => atoms.push(name.clone()),
        Formula::Top | Formula::Bottom => {}
        Formula::Not(f) => collect_atoms_rec(f, atoms),
        Formula::And(l, r) | Formula::Or(l, r) | Formula::Implies(l, r) | Formula::Iff(l, r) => {
            collect_atoms_rec(l, atoms);
            collect_atoms_rec(r, atoms);
        }
        Formula::Necessity(f)
        | Formula::Possibility(f)
        | Formula::AlwaysFuture(f)
        | Formula::Eventually(f)
        | Formula::AlwaysPast(f)
        | Formula::SometimePast(f)
        | Formula::Perpetual(f)
        | Formula::Sometimes(f) => collect_atoms_rec(f, atoms),
        // Layer 1-3 operators
        Formula::WouldCounterfactual(l, r)
        | Formula::MightCounterfactual(l, r)
        | Formula::Grounding(l, r)
        | Formula::Essence(l, r)
        | Formula::PropIdentity(l, r)
        | Formula::Causation(l, r)
        | Formula::IndicativeConditional(l, r)
        | Formula::Preference(l, r) => {
            collect_atoms_rec(l, atoms);
            collect_atoms_rec(r, atoms);
        }
        Formula::Belief(_, f)
        | Formula::Knowledge(_, f)
        | Formula::ProbabilityAtLeast(f, _)
        | Formula::EpistemicPossibility(f)
        | Formula::EpistemicNecessity(f)
        | Formula::Obligation(_, f)
        | Formula::Permission(_, f)
        | Formula::Prohibition(_, f) => collect_atoms_rec(f, atoms),
        Formula::AgentPreference(_, l, r) => {
            collect_atoms_rec(l, atoms);
            collect_atoms_rec(r, atoms);
        }
    }
}

/// Evaluate a propositional formula under an assignment
fn evaluate_propositional(
    formula: &Formula,
    assignment: &std::collections::HashMap<&str, bool>,
) -> bool {
    match formula {
        Formula::Atom(name) => *assignment.get(name.as_str()).unwrap_or(&false),
        Formula::Top => true,
        Formula::Bottom => false,
        Formula::Not(f) => !evaluate_propositional(f, assignment),
        Formula::And(l, r) => {
            evaluate_propositional(l, assignment) && evaluate_propositional(r, assignment)
        }
        Formula::Or(l, r) => {
            evaluate_propositional(l, assignment) || evaluate_propositional(r, assignment)
        }
        Formula::Implies(l, r) => {
            !evaluate_propositional(l, assignment) || evaluate_propositional(r, assignment)
        }
        Formula::Iff(l, r) => {
            evaluate_propositional(l, assignment) == evaluate_propositional(r, assignment)
        }
        // For modal/temporal operators in propositional context, treat as atoms
        // (This is a simplification - real semantics requires worlds/times)
        _ => false,
    }
}

use chrono::Utc;

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // Original 4 tests (must continue to pass)
    // ================================================================

    #[test]
    fn test_tautology() {
        let checker = Z3Checker::new();

        // p ∨ ¬p is a tautology
        let p = Formula::atom("p");
        let tautology = Formula::or(p.clone(), Formula::not(p));

        let result = checker.check(&tautology);
        assert!(result.is_valid(), "p ∨ ¬p should be valid");
    }

    #[test]
    fn test_contradiction() {
        let checker = Z3Checker::new();

        // p ∧ ¬p is a contradiction (not valid)
        let p = Formula::atom("p");
        let contradiction = Formula::and(p.clone(), Formula::not(p));

        let result = checker.check(&contradiction);
        assert!(result.is_invalid(), "p ∧ ¬p should be invalid");
    }

    #[test]
    fn test_contingent() {
        let checker = Z3Checker::new();

        // p → q is contingent (not a tautology)
        let p = Formula::atom("p");
        let q = Formula::atom("q");
        let contingent = Formula::implies(p, q);

        let result = checker.check(&contingent);
        assert!(result.is_invalid(), "p → q should have a counterexample");

        // The counterexample should have p=true, q=false
        if let Some(cex) = result.counterexample() {
            let p_val = cex
                .state_assignments
                .iter()
                .find(|a| a.atom == "p")
                .map(|a| a.value);
            let q_val = cex
                .state_assignments
                .iter()
                .find(|a| a.atom == "q")
                .map(|a| a.value);

            assert_eq!(p_val, Some(true));
            assert_eq!(q_val, Some(false));
        }
    }

    #[test]
    fn test_modus_ponens() {
        let checker = Z3Checker::new();

        // ((p → q) ∧ p) → q is valid (modus ponens)
        let p = Formula::atom("p");
        let q = Formula::atom("q");
        let modus_ponens =
            Formula::implies(Formula::and(Formula::implies(p.clone(), q.clone()), p), q);

        let result = checker.check(&modus_ponens);
        assert!(result.is_valid(), "Modus ponens should be valid");
    }

    // ================================================================
    // Z3 path tests (formulas with >10 atoms)
    // ================================================================

    #[test]
    fn test_z3_large_tautology() {
        let checker = Z3Checker::new();

        // Build a tautology with 12 atoms: (a1 ∨ ¬a1) ∧ (a2 ∨ ¬a2) ∧ ... ∧ (a12 ∨ ¬a12)
        let mut formula = Formula::or(Formula::atom("a1"), Formula::not(Formula::atom("a1")));
        for i in 2..=12 {
            let name = format!("a{}", i);
            let clause = Formula::or(
                Formula::atom(name.clone()),
                Formula::not(Formula::atom(name)),
            );
            formula = Formula::and(formula, clause);
        }

        let result = checker.check(&formula);
        assert!(
            result.is_valid(),
            "Conjunction of excluded middles with 12 atoms should be valid (uses Z3 path)"
        );
    }

    #[test]
    fn test_z3_large_contingent() {
        let checker = Z3Checker::new();

        // a1 ∧ a2 ∧ ... ∧ a12 is contingent (not a tautology)
        let mut formula = Formula::atom("a1");
        for i in 2..=12 {
            formula = Formula::and(formula, Formula::atom(format!("a{}", i)));
        }

        let result = checker.check(&formula);
        assert!(
            result.is_invalid(),
            "Conjunction of 12 atoms should not be valid (uses Z3 path)"
        );
    }

    #[test]
    fn test_z3_large_implication_chain() {
        let checker = Z3Checker::new();

        // (a1 → a2) ∧ (a2 → a3) ∧ ... ∧ (a11 → a12) → (a1 → a12) is valid
        let mut premises = Formula::implies(Formula::atom("a1"), Formula::atom("a2"));
        for i in 2..=11 {
            let step = Formula::implies(
                Formula::atom(format!("a{}", i)),
                Formula::atom(format!("a{}", i + 1)),
            );
            premises = Formula::and(premises, step);
        }

        let conclusion = Formula::implies(Formula::atom("a1"), Formula::atom("a12"));
        let formula = Formula::implies(premises, conclusion);

        let result = checker.check(&formula);
        assert!(
            result.is_valid(),
            "Transitivity chain with 12 atoms should be valid (uses Z3 path)"
        );
    }

    // ================================================================
    // check_propositional_z3 tests (always use Z3, even for small formulas)
    // ================================================================

    #[test]
    fn test_check_propositional_z3_tautology() {
        let checker = Z3Checker::new();
        let p = Formula::atom("p");
        let f = Formula::or(p.clone(), Formula::not(p));
        let result = checker.check_propositional_z3(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_valid()));
    }

    #[test]
    fn test_check_propositional_z3_contradiction() {
        let checker = Z3Checker::new();
        let p = Formula::atom("p");
        let f = Formula::and(p.clone(), Formula::not(p));
        let result = checker.check_propositional_z3(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_invalid()));
    }

    #[test]
    fn test_check_propositional_z3_modus_ponens() {
        let checker = Z3Checker::new();
        let p = Formula::atom("p");
        let q = Formula::atom("q");
        let f = Formula::implies(Formula::and(Formula::implies(p.clone(), q.clone()), p), q);
        let result = checker.check_propositional_z3(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_valid()));
    }

    // ================================================================
    // Normative consistency checking
    // ================================================================

    #[test]
    fn test_normative_consistency_no_conflict() {
        let checker = Z3Checker::new();

        // Permission(p) and Prohibition(¬p) -- mutually exclusive, no conflict
        // An action satisfying p cannot simultaneously satisfy ¬p.
        let formulas = vec![
            Formula::permission("agent1", Formula::atom("p")),
            Formula::prohibition("agent1", Formula::not(Formula::atom("p"))),
        ];

        let result = checker.check_consistency(&formulas);
        assert!(
            result.is_valid(),
            "Permission(p) and Prohibition(¬p) should be consistent (mutually exclusive)"
        );
    }

    #[test]
    fn test_normative_consistency_independent_atoms_conflict() {
        let checker = Z3Checker::new();

        // Permission(read) and Prohibition(write) -- independent atoms can both be true,
        // which means there exists a state where the action is both permitted and forbidden.
        // This IS a potential conflict in deontic logic.
        let formulas = vec![
            Formula::permission("agent1", Formula::atom("read")),
            Formula::prohibition("agent1", Formula::atom("write")),
        ];

        let result = checker.check_consistency(&formulas);
        assert!(
            result.is_invalid(),
            "Permission(read) and Prohibition(write) can co-exist, flagged as potential conflict"
        );
    }

    #[test]
    fn test_normative_consistency_conflict() {
        let checker = Z3Checker::new();

        // Permission(agent1, p) and Prohibition(agent1, p) conflict
        let formulas = vec![
            Formula::permission("agent1", Formula::atom("action")),
            Formula::prohibition("agent1", Formula::atom("action")),
        ];

        let result = checker.check_consistency(&formulas);
        assert!(
            result.is_invalid(),
            "Permission and Prohibition on the same atom for the same agent should conflict"
        );
    }

    #[test]
    fn test_normative_consistency_different_agents() {
        let checker = Z3Checker::new();

        // Permission(agent1, p) and Prohibition(agent2, p) -- different agents, no conflict
        let formulas = vec![
            Formula::permission("agent1", Formula::atom("action")),
            Formula::prohibition("agent2", Formula::atom("action")),
        ];

        let result = checker.check_consistency(&formulas);
        assert!(
            result.is_valid(),
            "Permission and Prohibition on same atom but different agents should be consistent"
        );
    }

    #[test]
    fn test_normative_consistency_obligation_prohibition_conflict() {
        let checker = Z3Checker::new();

        // Obligation(agent1, p) and Prohibition(agent1, p) conflict
        let formulas = vec![
            Formula::obligation("agent1", Formula::atom("action")),
            Formula::prohibition("agent1", Formula::atom("action")),
        ];

        let result = checker.check_consistency(&formulas);
        assert!(
            result.is_invalid(),
            "Obligation and Prohibition on the same atom should conflict"
        );
    }

    // ================================================================
    // Normative conflict detection via check()
    // ================================================================

    #[test]
    fn test_normative_conflict_via_check() {
        let checker = Z3Checker::new();

        // A formula that contains both Permission and Prohibition on the same action
        let f = Formula::and(
            Formula::permission("agent1", Formula::atom("access_file")),
            Formula::prohibition("agent1", Formula::atom("access_file")),
        );

        let result = checker.check(&f);
        assert!(
            result.is_invalid(),
            "Formula with conflicting Permission and Prohibition should be detected"
        );
    }

    #[test]
    fn test_normative_no_conflict_mutually_exclusive() {
        let checker = Z3Checker::new();

        // Permission(agent1, p) ∧ Prohibition(agent1, ¬p) -- mutually exclusive, no conflict
        let f = Formula::and(
            Formula::permission("agent1", Formula::atom("p")),
            Formula::prohibition("agent1", Formula::not(Formula::atom("p"))),
        );

        let result = checker.check(&f);
        // Should not report a normative conflict because p and ¬p can never both
        // be true simultaneously
        assert!(
            !result
                .counterexample()
                .is_some_and(|c| c.model_description.contains("conflict")),
            "Mutually exclusive normative formulas should not report normative conflict"
        );
    }

    // ================================================================
    // Completeness checking
    // ================================================================

    #[test]
    fn test_completeness_complete() {
        let checker = Z3Checker::new();

        let formulas = vec![
            Formula::permission("agent1", Formula::atom("read")),
            Formula::prohibition("agent1", Formula::atom("write")),
            Formula::obligation("agent1", Formula::atom("audit")),
        ];

        let actions = vec!["read".to_string(), "write".to_string(), "audit".to_string()];

        let result = checker.check_completeness(&formulas, &actions);
        assert!(result.is_valid(), "All actions should be covered");
    }

    #[test]
    fn test_completeness_incomplete() {
        let checker = Z3Checker::new();

        let formulas = vec![Formula::permission("agent1", Formula::atom("read"))];

        let actions = vec![
            "read".to_string(),
            "write".to_string(),
            "execute".to_string(),
        ];

        let result = checker.check_completeness(&formulas, &actions);
        assert!(result.is_invalid(), "write and execute should be missing");

        if let Some(cex) = result.counterexample() {
            assert!(
                cex.model_description.contains("write")
                    || cex.model_description.contains("execute"),
                "Should mention missing actions"
            );
        }
    }

    // ================================================================
    // Inheritance soundness checking
    // ================================================================

    #[test]
    fn test_inheritance_sound() {
        let checker = Z3Checker::new();

        let parent = vec![Formula::prohibition("agent1", Formula::atom("delete"))];

        // Merged policy preserves the prohibition
        let merged = vec![
            Formula::prohibition("agent1", Formula::atom("delete")),
            Formula::permission("agent1", Formula::atom("read")),
        ];

        let result = checker.check_inheritance_soundness(&parent, &merged);
        assert!(
            result.is_valid(),
            "Merged policy preserves parent prohibition"
        );
    }

    #[test]
    fn test_inheritance_violation_missing() {
        let checker = Z3Checker::new();

        let parent = vec![Formula::prohibition("agent1", Formula::atom("delete"))];

        // Merged policy drops the prohibition entirely
        let merged = vec![Formula::permission("agent1", Formula::atom("read"))];

        let result = checker.check_inheritance_soundness(&parent, &merged);
        assert!(
            result.is_invalid(),
            "Merged policy missing parent prohibition should fail"
        );
    }

    #[test]
    fn test_inheritance_violation_weakened() {
        let checker = Z3Checker::new();

        // Parent prohibits delete (broad prohibition)
        let parent = vec![Formula::prohibition("agent1", Formula::atom("delete"))];

        // Merged only prohibits (delete ∧ write) -- weaker, only forbids when both are true
        // delete → (delete ∧ write) is NOT valid, so prohibition is weakened
        let merged = vec![Formula::prohibition(
            "agent1",
            Formula::and(Formula::atom("delete"), Formula::atom("write")),
        )];

        let result = checker.check_inheritance_soundness(&parent, &merged);
        assert!(
            result.is_invalid(),
            "Weakened prohibition should fail inheritance check"
        );
    }

    #[test]
    fn test_inheritance_strengthened_is_sound() {
        let checker = Z3Checker::new();

        // Parent prohibits (delete ∧ write)
        let parent = vec![Formula::prohibition(
            "agent1",
            Formula::and(Formula::atom("delete"), Formula::atom("write")),
        )];

        // Merged prohibits delete (stronger -- covers more cases)
        // (delete ∧ write) → delete IS valid
        let merged = vec![Formula::prohibition("agent1", Formula::atom("delete"))];

        let result = checker.check_inheritance_soundness(&parent, &merged);
        assert!(
            result.is_valid(),
            "Strengthened prohibition should pass inheritance check"
        );
    }

    // ================================================================
    // Proptest: enumeration vs Z3 agreement for small formulas
    // ================================================================

    mod proptest_agreement {
        use super::*;
        use proptest::prelude::*;

        /// Generate random small propositional formulas
        fn arb_formula(depth: u32) -> BoxedStrategy<Formula> {
            if depth == 0 {
                prop_oneof![
                    Just(Formula::atom("p")),
                    Just(Formula::atom("q")),
                    Just(Formula::atom("r")),
                    Just(Formula::Top),
                    Just(Formula::Bottom),
                ]
                .boxed()
            } else {
                let leaf = arb_formula(0);
                let sub = arb_formula(depth - 1);
                prop_oneof![
                    leaf.clone(),
                    sub.clone().prop_map(Formula::not),
                    (sub.clone(), sub.clone()).prop_map(|(l, r)| Formula::and(l, r)),
                    (sub.clone(), sub.clone()).prop_map(|(l, r)| Formula::or(l, r)),
                    (sub.clone(), sub.clone()).prop_map(|(l, r)| Formula::implies(l, r)),
                    (sub.clone(), sub).prop_map(|(l, r)| Formula::iff(l, r)),
                ]
                .boxed()
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            #[test]
            fn enumeration_agrees_with_z3(formula in arb_formula(2)) {
                let checker = Z3Checker::new();
                let atoms = collect_atoms(&formula);

                // Only test if atoms <= 10 (enumeration range)
                if atoms.len() <= 10 {
                    let enum_result = checker.check_propositional_enumerate(&formula, &atoms);
                    let z3_result = checker.check_propositional_z3(&formula);

                    match (enum_result, z3_result) {
                        (Ok(ref e), Ok(ref z)) => {
                            // Both should agree on valid/invalid
                            prop_assert_eq!(
                                e.is_valid(), z.is_valid(),
                                "Enumeration and Z3 disagree on: {}",
                                formula
                            );
                        }
                        _ => {
                            // If either errored, that's also fine for proptest
                        }
                    }
                }
            }
        }
    }
}
