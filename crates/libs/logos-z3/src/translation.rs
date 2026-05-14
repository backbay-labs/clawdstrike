//! Translation from Logos formulas to Z3 AST
//!
//! Converts `logos_ffi::Formula` into Z3 boolean AST nodes for
//! satisfiability and validity checking via the Z3 SMT solver.

use std::collections::HashMap;

use logos_ffi::Formula;
use z3::ast::Bool;
use z3::Context;

use crate::Z3Error;

/// Tracks normative annotations extracted during formula translation.
/// Normative operators (Layer 3) are reduced to their inner propositional
/// content for Z3 solving, but the normative metadata is preserved here
/// for conflict/consistency analysis.
#[derive(Debug, Clone)]
pub struct NormativeAnnotation {
    /// The agent this annotation applies to
    pub agent: String,
    /// The kind of normative operator
    pub kind: NormativeKind,
    /// String representation of the inner formula
    pub inner_formula_repr: String,
}

/// The kind of normative deontic operator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormativeKind {
    Prohibition,
    Permission,
    Obligation,
}

/// Translates Logos `Formula` values into Z3 boolean AST nodes.
///
/// Maintains a cache of atom-to-Z3-variable mappings so that the same
/// atom string always maps to the same Z3 `Bool` constant within a
/// single context. Also tracks normative annotations encountered
/// during translation for downstream conflict analysis.
pub struct FormulaTranslator<'ctx> {
    ctx: &'ctx Context,
    /// Cache: atom name -> Z3 Bool variable
    atoms: HashMap<String, Bool<'ctx>>,
    /// Normative annotations collected during translation
    pub normative_annotations: Vec<NormativeAnnotation>,
}

impl<'ctx> FormulaTranslator<'ctx> {
    /// Create a new translator bound to the given Z3 context.
    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            atoms: HashMap::new(),
            normative_annotations: Vec::new(),
        }
    }

    /// Translate a Logos `Formula` into a Z3 `Bool` AST node.
    ///
    /// Supports:
    /// - Layer 0 propositional connectives (Atom, Top, Bottom, Not, And, Or, Implies, Iff)
    /// - Layer 3 normative operators (Prohibition, Permission, Obligation) -- reduced
    ///   to their inner formula, with annotations tracked separately
    ///
    /// Returns `Z3Error::UnsupportedFormula` for modal, temporal, epistemic,
    /// explanatory, and preference operators.
    pub fn translate(&mut self, formula: &Formula) -> Result<Bool<'ctx>, Z3Error> {
        match formula {
            // === Layer 0: Propositional connectives ===
            Formula::Atom(name) => {
                if let Some(existing) = self.atoms.get(name) {
                    // z3 Bool doesn't implement Clone, but we can recreate from the
                    // same context with the same name to get the same Z3 variable.
                    // Actually, we need to re-create it fresh. Let's store and return refs.
                    // The z3 crate internally ref-counts AST nodes, so creating the same
                    // named const twice yields the same node.
                    let _ = existing;
                }
                let z3_var = Bool::new_const(self.ctx, name.as_str());
                self.atoms
                    .entry(name.clone())
                    .or_insert_with(|| Bool::new_const(self.ctx, name.as_str()));
                Ok(z3_var)
            }
            Formula::Top => Ok(Bool::from_bool(self.ctx, true)),
            Formula::Bottom => Ok(Bool::from_bool(self.ctx, false)),
            Formula::Not(inner) => {
                let z3_inner = self.translate(inner)?;
                Ok(z3_inner.not())
            }
            Formula::And(left, right) => {
                let z3_left = self.translate(left)?;
                let z3_right = self.translate(right)?;
                Ok(Bool::and(self.ctx, &[&z3_left, &z3_right]))
            }
            Formula::Or(left, right) => {
                let z3_left = self.translate(left)?;
                let z3_right = self.translate(right)?;
                Ok(Bool::or(self.ctx, &[&z3_left, &z3_right]))
            }
            Formula::Implies(antecedent, consequent) => {
                let z3_ante = self.translate(antecedent)?;
                let z3_cons = self.translate(consequent)?;
                Ok(z3_ante.implies(&z3_cons))
            }
            Formula::Iff(left, right) => {
                let z3_left = self.translate(left)?;
                let z3_right = self.translate(right)?;
                Ok(z3_left.iff(&z3_right))
            }

            // === Layer 3: Normative operators ===
            // We translate the inner formula and track the normative annotation.
            Formula::Prohibition(agent, inner) => {
                self.normative_annotations.push(NormativeAnnotation {
                    agent: agent.0.clone(),
                    kind: NormativeKind::Prohibition,
                    inner_formula_repr: format!("{}", inner),
                });
                self.translate(inner)
            }
            Formula::Permission(agent, inner) => {
                self.normative_annotations.push(NormativeAnnotation {
                    agent: agent.0.clone(),
                    kind: NormativeKind::Permission,
                    inner_formula_repr: format!("{}", inner),
                });
                self.translate(inner)
            }
            Formula::Obligation(agent, inner) => {
                self.normative_annotations.push(NormativeAnnotation {
                    agent: agent.0.clone(),
                    kind: NormativeKind::Obligation,
                    inner_formula_repr: format!("{}", inner),
                });
                self.translate(inner)
            }

            // === Unsupported operators ===
            Formula::Necessity(_) | Formula::Possibility(_) => Err(Z3Error::UnsupportedFormula(
                "Modal operators (Necessity/Possibility) require Kripke semantics encoding"
                    .to_string(),
            )),
            Formula::AlwaysFuture(_)
            | Formula::Eventually(_)
            | Formula::AlwaysPast(_)
            | Formula::SometimePast(_)
            | Formula::Perpetual(_)
            | Formula::Sometimes(_) => Err(Z3Error::UnsupportedFormula(
                "Temporal operators require bounded model encoding".to_string(),
            )),
            Formula::WouldCounterfactual(_, _)
            | Formula::MightCounterfactual(_, _)
            | Formula::Grounding(_, _)
            | Formula::Essence(_, _)
            | Formula::PropIdentity(_, _)
            | Formula::Causation(_, _) => Err(Z3Error::UnsupportedFormula(
                "Explanatory operators (Layer 1) not yet supported".to_string(),
            )),
            Formula::Belief(_, _)
            | Formula::Knowledge(_, _)
            | Formula::ProbabilityAtLeast(_, _)
            | Formula::EpistemicPossibility(_)
            | Formula::EpistemicNecessity(_)
            | Formula::IndicativeConditional(_, _) => Err(Z3Error::UnsupportedFormula(
                "Epistemic operators (Layer 2) not yet supported".to_string(),
            )),
            Formula::Preference(_, _) | Formula::AgentPreference(_, _, _) => {
                Err(Z3Error::UnsupportedFormula(
                    "Preference operators not yet supported in Z3 encoding".to_string(),
                ))
            }
        }
    }

    /// Return all atom names encountered during translation, sorted.
    pub fn atom_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.atoms.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return a reference to the Z3 context.
    pub fn context(&self) -> &'ctx Context {
        self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_translate_atom() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        let f = Formula::atom("p");
        let result = translator.translate(&f);
        assert!(result.is_ok());
        assert_eq!(translator.atom_names(), vec!["p".to_string()]);
    }

    #[test]
    fn test_translate_top_bottom() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        assert!(translator.translate(&Formula::Top).is_ok());
        assert!(translator.translate(&Formula::Bottom).is_ok());
    }

    #[test]
    fn test_translate_propositional() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        // (p ∧ q) → (p ∨ q)
        let f = Formula::implies(
            Formula::and(Formula::atom("p"), Formula::atom("q")),
            Formula::or(Formula::atom("p"), Formula::atom("q")),
        );
        let result = translator.translate(&f);
        assert!(result.is_ok());

        let mut names = translator.atom_names();
        names.sort();
        assert_eq!(names, vec!["p".to_string(), "q".to_string()]);
    }

    #[test]
    fn test_translate_normative() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        let f = Formula::prohibition("agent1", Formula::atom("write_secrets"));
        let result = translator.translate(&f);
        assert!(result.is_ok());
        assert_eq!(translator.normative_annotations.len(), 1);
        assert_eq!(translator.normative_annotations[0].agent, "agent1");
        assert_eq!(
            translator.normative_annotations[0].kind,
            NormativeKind::Prohibition
        );
    }

    #[test]
    fn test_translate_unsupported_modal() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        let f = Formula::necessity(Formula::atom("p"));
        let result = translator.translate(&f);
        assert!(result.is_err());
        match result {
            Err(Z3Error::UnsupportedFormula(msg)) => {
                assert!(msg.contains("Modal"));
            }
            _ => panic!("Expected UnsupportedFormula error"),
        }
    }

    #[test]
    fn test_translate_iff() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut translator = FormulaTranslator::new(&ctx);

        let f = Formula::iff(Formula::atom("p"), Formula::atom("q"));
        let result = translator.translate(&f);
        assert!(result.is_ok());
    }
}
