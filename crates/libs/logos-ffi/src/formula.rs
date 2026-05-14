//! Formula types for the Logos proof system
//!
//! This module defines the AST for Logos formulas, covering all four layers:
//! - Layer 0: Core TM (Boolean, Modal, Temporal)
//! - Layer 1: Explanatory (Counterfactual, Grounding, Causal)
//! - Layer 2: Epistemic (Belief, Probability)
//! - Layer 3: Normative (Obligation, Permission, Preference)

use serde::{Deserialize, Serialize};

/// Agent identifier for epistemic and normative operators
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for AgentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Core formula type representing all Logos operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Formula {
    // === Layer 0: Core TM (Boolean + Modal + Temporal) ===
    /// Atomic proposition
    Atom(String),

    /// Logical true (⊤)
    Top,

    /// Logical false (⊥)
    Bottom,

    /// Negation (¬φ)
    Not(Box<Formula>),

    /// Conjunction (φ ∧ ψ)
    And(Box<Formula>, Box<Formula>),

    /// Disjunction (φ ∨ ψ)
    Or(Box<Formula>, Box<Formula>),

    /// Material implication (φ → ψ)
    Implies(Box<Formula>, Box<Formula>),

    /// Biconditional (φ ↔ ψ)
    Iff(Box<Formula>, Box<Formula>),

    // --- Modal operators (S5) ---
    /// Necessity (□φ) - True in all possible worlds
    Necessity(Box<Formula>),

    /// Possibility (◇φ) - True in some possible world
    Possibility(Box<Formula>),

    // --- Temporal operators (Linear) ---
    /// Always in the future (Gφ) - φ holds at all future moments
    AlwaysFuture(Box<Formula>),

    /// Eventually (Fφ) - φ holds at some future moment
    Eventually(Box<Formula>),

    /// Always in the past (Hφ) - φ held at all past moments
    AlwaysPast(Box<Formula>),

    /// Sometime past (Pφ) - φ held at some past moment
    SometimePast(Box<Formula>),

    /// Perpetually (△φ) - φ holds at all times (past and future)
    Perpetual(Box<Formula>),

    /// Sometimes (▽φ) - φ holds at some time
    Sometimes(Box<Formula>),

    // === Layer 1: Explanatory ===
    /// Would counterfactual (φ □→ ψ) - If φ were the case, ψ would be
    WouldCounterfactual(Box<Formula>, Box<Formula>),

    /// Might counterfactual (φ ◇→ ψ) - If φ were the case, ψ might be
    MightCounterfactual(Box<Formula>, Box<Formula>),

    /// Grounding (φ ≤ ψ) - φ is sufficient for ψ
    Grounding(Box<Formula>, Box<Formula>),

    /// Essence (φ ⊑ ψ) - φ is necessary for ψ
    Essence(Box<Formula>, Box<Formula>),

    /// Propositional identity (φ ≡ ψ) - φ just is ψ
    PropIdentity(Box<Formula>, Box<Formula>),

    /// Causation (φ ○→ ψ) - φ causes ψ
    Causation(Box<Formula>, Box<Formula>),

    // === Layer 2: Epistemic ===
    /// Belief (B_a(φ)) - Agent a believes φ
    Belief(AgentId, Box<Formula>),

    /// Knowledge (K_a(φ)) - Agent a knows φ
    Knowledge(AgentId, Box<Formula>),

    /// Probability threshold (Pr(φ) ≥ θ)
    ProbabilityAtLeast(Box<Formula>, f64),

    /// Epistemic possibility (M_i(φ)) - It might be that φ
    EpistemicPossibility(Box<Formula>),

    /// Epistemic necessity (M_u(φ)) - It must be that φ
    EpistemicNecessity(Box<Formula>),

    /// Indicative conditional (φ ⟹ ψ)
    IndicativeConditional(Box<Formula>, Box<Formula>),

    // === Layer 3: Normative ===
    /// Obligation (O_a(φ)) - Agent a is obligated to ensure φ
    Obligation(AgentId, Box<Formula>),

    /// Permission (P_a(φ)) - Agent a is permitted to do φ
    Permission(AgentId, Box<Formula>),

    /// Prohibition (F_a(φ)) - Agent a is forbidden from φ
    Prohibition(AgentId, Box<Formula>),

    /// Preference (φ ≺ ψ) - ψ is preferred over φ
    Preference(Box<Formula>, Box<Formula>),

    /// Agent preference (φ ≺_a ψ) - Agent a prefers ψ over φ
    AgentPreference(AgentId, Box<Formula>, Box<Formula>),
}

impl Formula {
    // === Constructors for Layer 0 ===

    /// Create an atomic proposition
    pub fn atom(name: impl Into<String>) -> Self {
        Self::Atom(name.into())
    }

    /// Logical true
    pub fn top() -> Self {
        Self::Top
    }

    /// Logical false
    pub fn bottom() -> Self {
        Self::Bottom
    }

    /// Negation
    #[allow(clippy::should_implement_trait)]
    pub fn not(f: Formula) -> Self {
        Self::Not(Box::new(f))
    }

    /// Conjunction
    pub fn and(left: Formula, right: Formula) -> Self {
        Self::And(Box::new(left), Box::new(right))
    }

    /// Disjunction
    pub fn or(left: Formula, right: Formula) -> Self {
        Self::Or(Box::new(left), Box::new(right))
    }

    /// Material implication
    pub fn implies(antecedent: Formula, consequent: Formula) -> Self {
        Self::Implies(Box::new(antecedent), Box::new(consequent))
    }

    /// Biconditional
    pub fn iff(left: Formula, right: Formula) -> Self {
        Self::Iff(Box::new(left), Box::new(right))
    }

    /// Necessity (□)
    pub fn necessity(f: Formula) -> Self {
        Self::Necessity(Box::new(f))
    }

    /// Possibility (◇)
    pub fn possibility(f: Formula) -> Self {
        Self::Possibility(Box::new(f))
    }

    /// Always future (G)
    pub fn always_future(f: Formula) -> Self {
        Self::AlwaysFuture(Box::new(f))
    }

    /// Eventually (F)
    pub fn eventually(f: Formula) -> Self {
        Self::Eventually(Box::new(f))
    }

    /// Always past (H)
    pub fn always_past(f: Formula) -> Self {
        Self::AlwaysPast(Box::new(f))
    }

    /// Sometime past (P)
    pub fn sometime_past(f: Formula) -> Self {
        Self::SometimePast(Box::new(f))
    }

    /// Perpetual (△)
    pub fn perpetual(f: Formula) -> Self {
        Self::Perpetual(Box::new(f))
    }

    /// Sometimes (▽)
    pub fn sometimes(f: Formula) -> Self {
        Self::Sometimes(Box::new(f))
    }

    // === Constructors for Layer 1 (Explanatory) ===

    /// Would counterfactual (□→)
    pub fn would_counterfactual(antecedent: Formula, consequent: Formula) -> Self {
        Self::WouldCounterfactual(Box::new(antecedent), Box::new(consequent))
    }

    /// Might counterfactual (◇→)
    pub fn might_counterfactual(antecedent: Formula, consequent: Formula) -> Self {
        Self::MightCounterfactual(Box::new(antecedent), Box::new(consequent))
    }

    /// Grounding (≤)
    pub fn grounding(ground: Formula, grounded: Formula) -> Self {
        Self::Grounding(Box::new(ground), Box::new(grounded))
    }

    /// Essence (⊑)
    pub fn essence(essential: Formula, bearer: Formula) -> Self {
        Self::Essence(Box::new(essential), Box::new(bearer))
    }

    /// Propositional identity (≡)
    pub fn prop_identity(left: Formula, right: Formula) -> Self {
        Self::PropIdentity(Box::new(left), Box::new(right))
    }

    /// Causation (○→)
    pub fn causes(cause: Formula, effect: Formula) -> Self {
        Self::Causation(Box::new(cause), Box::new(effect))
    }

    // === Constructors for Layer 2 (Epistemic) ===

    /// Belief (B_a)
    pub fn belief(agent: impl Into<AgentId>, f: Formula) -> Self {
        Self::Belief(agent.into(), Box::new(f))
    }

    /// Knowledge (K_a)
    pub fn knowledge(agent: impl Into<AgentId>, f: Formula) -> Self {
        Self::Knowledge(agent.into(), Box::new(f))
    }

    /// Probability at least θ
    pub fn probability_at_least(f: Formula, threshold: f64) -> Self {
        Self::ProbabilityAtLeast(Box::new(f), threshold.clamp(0.0, 1.0))
    }

    /// Epistemic possibility (M_i)
    pub fn epistemic_possibility(f: Formula) -> Self {
        Self::EpistemicPossibility(Box::new(f))
    }

    /// Epistemic necessity (M_u)
    pub fn epistemic_necessity(f: Formula) -> Self {
        Self::EpistemicNecessity(Box::new(f))
    }

    /// Indicative conditional (⟹)
    pub fn indicative(antecedent: Formula, consequent: Formula) -> Self {
        Self::IndicativeConditional(Box::new(antecedent), Box::new(consequent))
    }

    // === Constructors for Layer 3 (Normative) ===

    /// Obligation (O_a)
    pub fn obligation(agent: impl Into<AgentId>, f: Formula) -> Self {
        Self::Obligation(agent.into(), Box::new(f))
    }

    /// Permission (P_a)
    pub fn permission(agent: impl Into<AgentId>, f: Formula) -> Self {
        Self::Permission(agent.into(), Box::new(f))
    }

    /// Prohibition (F_a) - Defined as O_a(¬φ)
    pub fn prohibition(agent: impl Into<AgentId>, f: Formula) -> Self {
        Self::Prohibition(agent.into(), Box::new(f))
    }

    /// Preference (≺)
    pub fn preference(less: Formula, more: Formula) -> Self {
        Self::Preference(Box::new(less), Box::new(more))
    }

    /// Agent preference (≺_a)
    pub fn agent_preference(agent: impl Into<AgentId>, less: Formula, more: Formula) -> Self {
        Self::AgentPreference(agent.into(), Box::new(less), Box::new(more))
    }

    // === Derived operators ===

    /// Dual of necessity: ◇φ ≡ ¬□¬φ
    pub fn possibility_via_necessity(f: Formula) -> Self {
        Self::not(Self::necessity(Self::not(f)))
    }

    /// Permission via obligation: P_a(φ) ≡ ¬O_a(¬φ)
    pub fn permission_via_obligation(agent: impl Into<AgentId>, f: Formula) -> Self {
        let agent = agent.into();
        Self::not(Self::obligation(agent, Self::not(f)))
    }

    /// Check if formula contains any epistemic operators
    pub fn is_epistemic(&self) -> bool {
        match self {
            Self::Belief(_, _)
            | Self::Knowledge(_, _)
            | Self::ProbabilityAtLeast(_, _)
            | Self::EpistemicPossibility(_)
            | Self::EpistemicNecessity(_)
            | Self::IndicativeConditional(_, _) => true,
            Self::Not(f)
            | Self::Necessity(f)
            | Self::Possibility(f)
            | Self::AlwaysFuture(f)
            | Self::Eventually(f)
            | Self::AlwaysPast(f)
            | Self::SometimePast(f)
            | Self::Perpetual(f)
            | Self::Sometimes(f) => f.is_epistemic(),
            Self::And(l, r)
            | Self::Or(l, r)
            | Self::Implies(l, r)
            | Self::Iff(l, r)
            | Self::WouldCounterfactual(l, r)
            | Self::MightCounterfactual(l, r)
            | Self::Grounding(l, r)
            | Self::Essence(l, r)
            | Self::PropIdentity(l, r)
            | Self::Causation(l, r)
            | Self::Preference(l, r) => l.is_epistemic() || r.is_epistemic(),
            Self::AgentPreference(_, l, r) => l.is_epistemic() || r.is_epistemic(),
            Self::Obligation(_, f) | Self::Permission(_, f) | Self::Prohibition(_, f) => {
                f.is_epistemic()
            }
            _ => false,
        }
    }

    /// Check if formula contains any normative operators
    pub fn is_normative(&self) -> bool {
        match self {
            Self::Obligation(_, _)
            | Self::Permission(_, _)
            | Self::Prohibition(_, _)
            | Self::Preference(_, _)
            | Self::AgentPreference(_, _, _) => true,
            Self::Not(f)
            | Self::Necessity(f)
            | Self::Possibility(f)
            | Self::AlwaysFuture(f)
            | Self::Eventually(f)
            | Self::AlwaysPast(f)
            | Self::SometimePast(f)
            | Self::Perpetual(f)
            | Self::Sometimes(f)
            | Self::Belief(_, f)
            | Self::Knowledge(_, f)
            | Self::ProbabilityAtLeast(f, _)
            | Self::EpistemicPossibility(f)
            | Self::EpistemicNecessity(f) => f.is_normative(),
            Self::And(l, r)
            | Self::Or(l, r)
            | Self::Implies(l, r)
            | Self::Iff(l, r)
            | Self::WouldCounterfactual(l, r)
            | Self::MightCounterfactual(l, r)
            | Self::Grounding(l, r)
            | Self::Essence(l, r)
            | Self::PropIdentity(l, r)
            | Self::Causation(l, r)
            | Self::IndicativeConditional(l, r) => l.is_normative() || r.is_normative(),
            _ => false,
        }
    }

    /// Get the layer (0-3) required for this formula
    pub fn required_layer(&self) -> u8 {
        if self.is_normative() {
            3
        } else if self.is_epistemic() {
            2
        } else if self.is_explanatory() {
            1
        } else {
            0
        }
    }

    fn is_explanatory(&self) -> bool {
        match self {
            Self::WouldCounterfactual(_, _)
            | Self::MightCounterfactual(_, _)
            | Self::Grounding(_, _)
            | Self::Essence(_, _)
            | Self::PropIdentity(_, _)
            | Self::Causation(_, _) => true,
            Self::Not(f)
            | Self::Necessity(f)
            | Self::Possibility(f)
            | Self::AlwaysFuture(f)
            | Self::Eventually(f)
            | Self::AlwaysPast(f)
            | Self::SometimePast(f)
            | Self::Perpetual(f)
            | Self::Sometimes(f) => f.is_explanatory(),
            Self::And(l, r) | Self::Or(l, r) | Self::Implies(l, r) | Self::Iff(l, r) => {
                l.is_explanatory() || r.is_explanatory()
            }
            _ => false,
        }
    }
}

impl std::ops::Not for Formula {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::Not(Box::new(self))
    }
}

/// Pretty-print a formula in mathematical notation
impl std::fmt::Display for Formula {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Atom(name) => write!(f, "{}", name),
            Self::Top => write!(f, "⊤"),
            Self::Bottom => write!(f, "⊥"),
            Self::Not(inner) => write!(f, "¬{}", inner),
            Self::And(l, r) => write!(f, "({} ∧ {})", l, r),
            Self::Or(l, r) => write!(f, "({} ∨ {})", l, r),
            Self::Implies(l, r) => write!(f, "({} → {})", l, r),
            Self::Iff(l, r) => write!(f, "({} ↔ {})", l, r),
            Self::Necessity(inner) => write!(f, "□{}", inner),
            Self::Possibility(inner) => write!(f, "◇{}", inner),
            Self::AlwaysFuture(inner) => write!(f, "G{}", inner),
            Self::Eventually(inner) => write!(f, "F{}", inner),
            Self::AlwaysPast(inner) => write!(f, "H{}", inner),
            Self::SometimePast(inner) => write!(f, "P{}", inner),
            Self::Perpetual(inner) => write!(f, "△{}", inner),
            Self::Sometimes(inner) => write!(f, "▽{}", inner),
            Self::WouldCounterfactual(l, r) => write!(f, "({} □→ {})", l, r),
            Self::MightCounterfactual(l, r) => write!(f, "({} ◇→ {})", l, r),
            Self::Grounding(l, r) => write!(f, "({} ≤ {})", l, r),
            Self::Essence(l, r) => write!(f, "({} ⊑ {})", l, r),
            Self::PropIdentity(l, r) => write!(f, "({} ≡ {})", l, r),
            Self::Causation(l, r) => write!(f, "({} ○→ {})", l, r),
            Self::Belief(a, inner) => write!(f, "B_{}({})", a.0, inner),
            Self::Knowledge(a, inner) => write!(f, "K_{}({})", a.0, inner),
            Self::ProbabilityAtLeast(inner, t) => write!(f, "Pr({}) ≥ {:.2}", inner, t),
            Self::EpistemicPossibility(inner) => write!(f, "M_i({})", inner),
            Self::EpistemicNecessity(inner) => write!(f, "M_u({})", inner),
            Self::IndicativeConditional(l, r) => write!(f, "({} ⟹ {})", l, r),
            Self::Obligation(a, inner) => write!(f, "O_{}({})", a.0, inner),
            Self::Permission(a, inner) => write!(f, "P_{}({})", a.0, inner),
            Self::Prohibition(a, inner) => write!(f, "F_{}({})", a.0, inner),
            Self::Preference(l, r) => write!(f, "({} ≺ {})", l, r),
            Self::AgentPreference(a, l, r) => write!(f, "({} ≺_{} {})", l, a.0, r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atom_creation() {
        let p = Formula::atom("p");
        assert!(matches!(p, Formula::Atom(ref s) if s == "p"));
    }

    #[test]
    fn test_layer_detection() {
        // Layer 0
        let modal = Formula::necessity(Formula::atom("p"));
        assert_eq!(modal.required_layer(), 0);

        // Layer 1
        let counterfactual = Formula::would_counterfactual(Formula::atom("p"), Formula::atom("q"));
        assert_eq!(counterfactual.required_layer(), 1);

        // Layer 2
        let belief = Formula::belief("alice", Formula::atom("p"));
        assert_eq!(belief.required_layer(), 2);

        // Layer 3
        let obligation = Formula::obligation("bob", Formula::atom("p"));
        assert_eq!(obligation.required_layer(), 3);
    }

    #[test]
    fn test_pretty_print() {
        let k_axiom = Formula::implies(
            Formula::necessity(Formula::implies(Formula::atom("p"), Formula::atom("q"))),
            Formula::implies(
                Formula::necessity(Formula::atom("p")),
                Formula::necessity(Formula::atom("q")),
            ),
        );

        let printed = format!("{}", k_axiom);
        assert!(printed.contains("□"));
        assert!(printed.contains("→"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let formula = Formula::and(
            Formula::necessity(Formula::atom("p")),
            Formula::eventually(Formula::atom("q")),
        );

        let json = match serde_json::to_string(&formula) {
            Ok(json) => json,
            Err(err) => panic!("failed to serialize formula: {err}"),
        };
        let recovered: Formula = match serde_json::from_str(&json) {
            Ok(recovered) => recovered,
            Err(err) => panic!("failed to deserialize formula: {err}"),
        };

        assert_eq!(formula, recovered);
    }
}
