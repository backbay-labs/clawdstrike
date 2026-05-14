//! Z3 solver wrapper for satisfiability and validity checking.
//!
//! Provides `Z3SolverWrapper` which manages Z3 solver lifecycle (config,
//! context, solver, model extraction) and exposes high-level `check_valid`
//! and `check_sat` methods.

use logos_ffi::{Counterexample, Formula, ProofResult, StateAssignment};
use z3::{ast::Bool, Config, Context, Model, Params, SatResult, Solver};

use crate::translation::FormulaTranslator;
use crate::{Z3Config, Z3Error};

/// Wrapper around Z3 solver lifecycle.
///
/// Each check creates a fresh Z3 context and solver to avoid cross-contamination
/// between independent queries.
pub struct Z3SolverWrapper {
    config: Z3Config,
}

impl Z3SolverWrapper {
    /// Create a new solver wrapper with the given configuration.
    pub fn new(config: Z3Config) -> Self {
        Self { config }
    }

    /// Check if a formula is valid (its negation is unsatisfiable).
    ///
    /// Returns:
    /// - `ProofResult::Valid` if the negation is unsatisfiable (formula is a tautology)
    /// - `ProofResult::Invalid` with counterexample if the negation is satisfiable
    /// - `ProofResult::Unknown` if Z3 could not determine satisfiability
    pub fn check_valid(&self, formula: &Formula) -> Result<ProofResult, Z3Error> {
        let mut z3_cfg = Config::new();
        z3_cfg.set_model_generation(true);
        if self.config.timeout_ms > 0 {
            z3_cfg.set_timeout_msec(self.config.timeout_ms);
        }

        let ctx = Context::new(&z3_cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        // Translate the formula, then negate it
        let z3_formula = translator
            .translate(formula)
            .map_err(|e| Z3Error::Translation(e.to_string()))?;
        let negated = z3_formula.not();

        let solver = Solver::new(&ctx);

        // Set solver timeout via params
        if self.config.timeout_ms > 0 {
            let mut params = Params::new(&ctx);
            // timeout parameter is in milliseconds as u32
            let timeout_ms = if self.config.timeout_ms > u64::from(u32::MAX) {
                u32::MAX
            } else {
                self.config.timeout_ms as u32
            };
            params.set_u32("timeout", timeout_ms);
            solver.set_params(&params);
        }

        // Assert the negated formula
        solver.assert(&negated);

        match solver.check() {
            SatResult::Unsat => {
                // Negation is unsatisfiable => formula is valid
                let receipt =
                    logos_ffi::ProofReceipt::new(formula.clone(), vec![]).with_z3_valid(true);
                Ok(ProofResult::Valid(receipt))
            }
            SatResult::Sat => {
                // Negation is satisfiable => formula is invalid, extract counterexample
                let cex = if let Some(model) = solver.get_model() {
                    self.extract_counterexample(&model, &translator, formula)
                } else {
                    Counterexample::simple(formula.clone(), vec![])
                };
                Ok(ProofResult::Invalid(cex))
            }
            SatResult::Unknown => Ok(ProofResult::Unknown {
                reason: "Z3 returned unknown (possibly timeout or incomplete theory)".to_string(),
            }),
        }
    }

    /// Check if a formula is satisfiable (has at least one model).
    ///
    /// Returns:
    /// - `ProofResult::Valid` with a satisfying assignment if satisfiable
    /// - `ProofResult::Invalid` if unsatisfiable (the formula is a contradiction)
    /// - `ProofResult::Unknown` if Z3 could not determine satisfiability
    pub fn check_sat(&self, formula: &Formula) -> Result<ProofResult, Z3Error> {
        let mut z3_cfg = Config::new();
        z3_cfg.set_model_generation(true);
        if self.config.timeout_ms > 0 {
            z3_cfg.set_timeout_msec(self.config.timeout_ms);
        }

        let ctx = Context::new(&z3_cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        let z3_formula = translator
            .translate(formula)
            .map_err(|e| Z3Error::Translation(e.to_string()))?;

        let solver = Solver::new(&ctx);

        if self.config.timeout_ms > 0 {
            let mut params = Params::new(&ctx);
            let timeout_ms = if self.config.timeout_ms > u64::from(u32::MAX) {
                u32::MAX
            } else {
                self.config.timeout_ms as u32
            };
            params.set_u32("timeout", timeout_ms);
            solver.set_params(&params);
        }

        solver.assert(&z3_formula);

        match solver.check() {
            SatResult::Sat => {
                // Satisfiable - return valid with a satisfying model
                let receipt =
                    logos_ffi::ProofReceipt::new(formula.clone(), vec![]).with_z3_valid(true);
                Ok(ProofResult::Valid(receipt))
            }
            SatResult::Unsat => {
                // Unsatisfiable - formula is a contradiction
                let cex = Counterexample::simple(formula.clone(), vec![]);
                Ok(ProofResult::Invalid(cex))
            }
            SatResult::Unknown => Ok(ProofResult::Unknown {
                reason: "Z3 returned unknown (possibly timeout or incomplete theory)".to_string(),
            }),
        }
    }

    /// Extract a counterexample from a Z3 model.
    ///
    /// Evaluates each atom in the translated formula against the model
    /// to produce `StateAssignment` values.
    fn extract_counterexample(
        &self,
        model: &Model<'_>,
        translator: &FormulaTranslator<'_>,
        formula: &Formula,
    ) -> Counterexample {
        let atom_names = translator.atom_names();
        let ctx = translator.context();

        let state_assignments: Vec<StateAssignment> = atom_names
            .iter()
            .map(|name| {
                let z3_var = Bool::new_const(ctx, name.as_str());
                let value = model
                    .eval(&z3_var, true)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                StateAssignment {
                    atom: name.clone(),
                    world: None,
                    time: None,
                    value,
                }
            })
            .collect();

        Counterexample::simple(formula.clone(), state_assignments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_wrapper() -> Z3SolverWrapper {
        Z3SolverWrapper::new(Z3Config::default())
    }

    #[test]
    fn test_valid_tautology() {
        let wrapper = default_wrapper();
        // p | !p
        let p = Formula::atom("p");
        let f = Formula::or(p.clone(), Formula::not(p));
        let result = wrapper.check_valid(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_valid()));
    }

    #[test]
    fn test_invalid_contingent() {
        let wrapper = default_wrapper();
        // p -> q  is not valid
        let f = Formula::implies(Formula::atom("p"), Formula::atom("q"));
        let result = wrapper.check_valid(&f);
        assert!(result.is_ok());
        let result = result.expect("should be ok");
        assert!(result.is_invalid());

        // Counterexample should have p=true, q=false
        if let Some(cex) = result.counterexample() {
            let p_val = cex.state_assignments.iter().find(|a| a.atom == "p");
            let q_val = cex.state_assignments.iter().find(|a| a.atom == "q");
            assert!(p_val.is_some());
            assert!(q_val.is_some());
            assert!(p_val.is_some_and(|a| a.value));
            assert!(q_val.is_none_or(|a| !a.value));
        } else {
            panic!("Expected counterexample");
        }
    }

    #[test]
    fn test_sat_satisfiable() {
        let wrapper = default_wrapper();
        // p & q is satisfiable
        let f = Formula::and(Formula::atom("p"), Formula::atom("q"));
        let result = wrapper.check_sat(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_valid()));
    }

    #[test]
    fn test_sat_contradiction() {
        let wrapper = default_wrapper();
        // p & !p is unsatisfiable
        let p = Formula::atom("p");
        let f = Formula::and(p.clone(), Formula::not(p));
        let result = wrapper.check_sat(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_invalid()));
    }

    #[test]
    fn test_unsupported_modal() {
        let wrapper = default_wrapper();
        let f = Formula::necessity(Formula::atom("p"));
        let result = wrapper.check_valid(&f);
        assert!(result.is_err());
    }

    #[test]
    fn test_modus_ponens_z3() {
        let wrapper = default_wrapper();
        // ((p -> q) & p) -> q  is valid
        let p = Formula::atom("p");
        let q = Formula::atom("q");
        let f = Formula::implies(Formula::and(Formula::implies(p.clone(), q.clone()), p), q);
        let result = wrapper.check_valid(&f);
        assert!(result.is_ok());
        assert!(result.as_ref().ok().is_some_and(|r| r.is_valid()));
    }
}
