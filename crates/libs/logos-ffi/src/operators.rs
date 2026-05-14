//! Logos axiom schemas and inference rules
//!
//! This module defines the axiom schemas and inference rules for the
//! TM (Tense and Modality) logic system.

use crate::formula::Formula;
use serde::{Deserialize, Serialize};

/// Axiom schemas for the TM logic system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AxiomSchema {
    // === Modal Axioms (S5) ===
    /// MT: □φ → φ (necessity implies actuality)
    ModalT,
    /// M4: □φ → □□φ (necessity iterates)
    Modal4,
    /// MB: φ → □◇φ (actuality implies necessary possibility)
    ModalB,
    /// MK: □(φ → ψ) → (□φ → □ψ) (modal distribution)
    ModalK,

    // === Temporal Axioms ===
    /// T4: Gφ → GGφ (future is transitive)
    Temporal4,
    /// TA: φ → GPφ (present becomes past)
    TemporalA,
    /// TL: △φ → GPφ (perpetuity implies past occurrence)
    TemporalL,

    // === Bimodal Interaction ===
    /// MF: □φ → □Gφ (necessity persists forward)
    ModalFuture,
    /// TF: □φ → G□φ (necessity is temporally stable)
    TemporalFuture,
}

impl AxiomSchema {
    /// Instantiate an axiom schema with a formula
    pub fn instantiate(&self, phi: Formula, psi: Option<Formula>) -> Formula {
        match self {
            // □φ → φ
            Self::ModalT => Formula::implies(Formula::necessity(phi.clone()), phi),

            // □φ → □□φ
            Self::Modal4 => Formula::implies(
                Formula::necessity(phi.clone()),
                Formula::necessity(Formula::necessity(phi)),
            ),

            // φ → □◇φ
            Self::ModalB => {
                Formula::implies(phi.clone(), Formula::necessity(Formula::possibility(phi)))
            }

            // □(φ → ψ) → (□φ → □ψ)
            Self::ModalK => {
                let psi = psi.unwrap_or_else(|| Formula::atom("ψ"));
                Formula::implies(
                    Formula::necessity(Formula::implies(phi.clone(), psi.clone())),
                    Formula::implies(Formula::necessity(phi), Formula::necessity(psi)),
                )
            }

            // Gφ → GGφ
            Self::Temporal4 => Formula::implies(
                Formula::always_future(phi.clone()),
                Formula::always_future(Formula::always_future(phi)),
            ),

            // φ → GPφ
            Self::TemporalA => Formula::implies(
                phi.clone(),
                Formula::always_future(Formula::sometime_past(phi)),
            ),

            // △φ → GPφ
            Self::TemporalL => Formula::implies(
                Formula::perpetual(phi.clone()),
                Formula::always_future(Formula::sometime_past(phi)),
            ),

            // □φ → □Gφ
            Self::ModalFuture => Formula::implies(
                Formula::necessity(phi.clone()),
                Formula::necessity(Formula::always_future(phi)),
            ),

            // □φ → G□φ
            Self::TemporalFuture => Formula::implies(
                Formula::necessity(phi.clone()),
                Formula::always_future(Formula::necessity(phi)),
            ),
        }
    }

    /// Get the name of this axiom schema
    pub fn name(&self) -> &'static str {
        match self {
            Self::ModalT => "MT",
            Self::Modal4 => "M4",
            Self::ModalB => "MB",
            Self::ModalK => "MK",
            Self::Temporal4 => "T4",
            Self::TemporalA => "TA",
            Self::TemporalL => "TL",
            Self::ModalFuture => "MF",
            Self::TemporalFuture => "TF",
        }
    }
}

/// Inference rules for the TM logic system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InferenceRule {
    /// Modus Ponens: From φ and φ → ψ, infer ψ
    ModusPonens,
    /// Modal K: From φ → ψ, infer □φ → □ψ
    ModalK,
    /// Temporal K: From φ → ψ, infer Gφ → Gψ
    TemporalK,
    /// Temporal Duality: Fφ ≡ ¬G¬φ
    TemporalDuality,
    /// Weakening: From φ, infer φ ∨ ψ
    Weakening,
    /// Axiom: Introduce an axiom instance
    Axiom,
    /// Assumption: Introduce a hypothesis
    Assumption,
}

impl InferenceRule {
    /// Get the name of this inference rule
    pub fn name(&self) -> &'static str {
        match self {
            Self::ModusPonens => "MP",
            Self::ModalK => "MK",
            Self::TemporalK => "TK",
            Self::TemporalDuality => "TD",
            Self::Weakening => "W",
            Self::Axiom => "Ax",
            Self::Assumption => "As",
        }
    }
}

/// Perpetuity principles (P1-P6) connecting modal and temporal operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerpetuityPrinciple {
    /// P1: □φ → △φ (what is necessary is always the case)
    P1,
    /// P2: ▽φ → ◇φ (what is sometimes the case is possible)
    P2,
    /// P3: □φ → □△φ (necessity of perpetuity)
    P3,
    /// P4: ◇▽φ → ◇φ (possibility of occurrence)
    P4,
    /// P5: ◇▽φ → △◇φ (persistent possibility)
    P5,
    /// P6: ▽□φ → □△φ (occurrent necessity is perpetual)
    P6,
}

impl PerpetuityPrinciple {
    /// Create the formula for this perpetuity principle
    pub fn formula(&self, phi: Formula) -> Formula {
        match self {
            // □φ → △φ
            Self::P1 => Formula::implies(Formula::necessity(phi.clone()), Formula::perpetual(phi)),

            // ▽φ → ◇φ
            Self::P2 => {
                Formula::implies(Formula::sometimes(phi.clone()), Formula::possibility(phi))
            }

            // □φ → □△φ
            Self::P3 => Formula::implies(
                Formula::necessity(phi.clone()),
                Formula::necessity(Formula::perpetual(phi)),
            ),

            // ◇▽φ → ◇φ
            Self::P4 => Formula::implies(
                Formula::possibility(Formula::sometimes(phi.clone())),
                Formula::possibility(phi),
            ),

            // ◇▽φ → △◇φ
            Self::P5 => Formula::implies(
                Formula::possibility(Formula::sometimes(phi.clone())),
                Formula::perpetual(Formula::possibility(phi)),
            ),

            // ▽□φ → □△φ
            Self::P6 => Formula::implies(
                Formula::sometimes(Formula::necessity(phi.clone())),
                Formula::necessity(Formula::perpetual(phi)),
            ),
        }
    }

    /// Get the name of this principle
    pub fn name(&self) -> &'static str {
        match self {
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
            Self::P4 => "P4",
            Self::P5 => "P5",
            Self::P6 => "P6",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axiom_instantiation() {
        let p = Formula::atom("p");

        // MT: □p → p
        let mt = AxiomSchema::ModalT.instantiate(p.clone(), None);
        assert!(matches!(mt, Formula::Implies(_, _)));

        let printed = format!("{}", mt);
        assert!(printed.contains("□"));
        assert!(printed.contains("→"));
    }

    #[test]
    fn test_perpetuity_principles() {
        let p = Formula::atom("p");

        // P1: □p → △p
        let p1 = PerpetuityPrinciple::P1.formula(p.clone());
        let printed = format!("{}", p1);
        assert!(printed.contains("□"));
        assert!(printed.contains("△"));
    }

    #[test]
    fn test_modal_k() {
        let p = Formula::atom("p");
        let q = Formula::atom("q");

        // MK: □(p → q) → (□p → □q)
        let mk = AxiomSchema::ModalK.instantiate(p, Some(q));
        let printed = format!("{}", mk);
        assert!(printed.contains("□"));
    }
}
