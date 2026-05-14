//! Formal routing rule specification for kernel scheduling
//!
//! This module provides types for expressing routing rules as formal logic,
//! enabling verification of completeness and consistency.

use crate::{Formula, Justification, ProofReceipt, ProofStep};
use serde::{Deserialize, Serialize};

/// A routing rule with formal specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule name for identification
    pub name: String,

    /// Condition formula (when this rule applies)
    pub condition: Formula,

    /// Target toolchain (codex, claude, opencode, crush)
    pub toolchain: String,

    /// Whether to use speculation for this rule
    pub speculate: bool,

    /// Confidence bound for speculation decisions
    pub confidence: f64,

    /// Priority (higher = checked first)
    pub priority: i32,
}

impl RoutingRule {
    /// Create a new routing rule
    pub fn new(name: impl Into<String>, condition: Formula, toolchain: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            condition,
            toolchain: toolchain.into(),
            speculate: false,
            confidence: 1.0,
            priority: 0,
        }
    }

    /// Set speculation mode
    pub fn with_speculation(mut self, speculate: bool, confidence: f64) -> Self {
        self.speculate = speculate;
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// Complete routing specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSpec {
    /// All routing rules
    pub rules: Vec<RoutingRule>,

    /// Default toolchain when no rule matches
    pub default_toolchain: String,

    /// Issue type atoms (for formula construction)
    pub issue_atoms: Vec<String>,
}

impl RoutingSpec {
    /// Create a new routing spec
    pub fn new(default_toolchain: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            default_toolchain: default_toolchain.into(),
            issue_atoms: Vec::new(),
        }
    }

    /// Add a routing rule
    pub fn add_rule(&mut self, rule: RoutingRule) {
        self.rules.push(rule);
    }

    /// Define issue type atoms
    pub fn with_atoms(mut self, atoms: Vec<String>) -> Self {
        self.issue_atoms = atoms;
        self
    }

    /// Verify that all issue types have a matching rule (completeness)
    ///
    /// Returns Ok with proof if complete, or Err with gaps
    pub fn verify_completeness(&self) -> Result<ProofReceipt, Vec<CompletenessGap>> {
        let mut gaps = Vec::new();

        // Check each atom has at least one rule that could match
        for atom in &self.issue_atoms {
            let mut has_matching_rule = false;

            for rule in &self.rules {
                // Check if this rule's condition could be satisfied when atom is true
                if condition_covers_atom(&rule.condition, atom) {
                    has_matching_rule = true;
                    break;
                }
            }

            if !has_matching_rule {
                gaps.push(CompletenessGap {
                    issue_type: atom.clone(),
                    suggestion: format!(
                        "Add rule for {} or ensure default toolchain handles it",
                        atom
                    ),
                });
            }
        }

        if gaps.is_empty() {
            Ok(ProofReceipt::new(
                Formula::top(), // Completeness proven
                vec![ProofStep {
                    step_num: 1,
                    depth: 0,
                    formula: Formula::top(),
                    justification: Justification::Hypothesis,
                    premises: vec![],
                    explanation: Some("All issue types covered by rules or default".to_string()),
                }],
            ))
        } else {
            Err(gaps)
        }
    }

    /// Verify that no two rules conflict (consistency)
    ///
    /// Returns Ok with proof if consistent, or Err with conflicts
    pub fn verify_consistency(&self) -> Result<ProofReceipt, Vec<RuleConflict>> {
        let mut conflicts = Vec::new();

        // Check each pair of rules for conflicts
        for (i, rule_a) in self.rules.iter().enumerate() {
            for rule_b in self.rules.iter().skip(i + 1) {
                // Rules conflict if:
                // 1. Their conditions can both be true simultaneously
                // 2. They route to different toolchains
                // 3. They have the same priority
                if rule_a.toolchain != rule_b.toolchain
                    && rule_a.priority == rule_b.priority
                    && conditions_can_overlap(&rule_a.condition, &rule_b.condition)
                {
                    conflicts.push(RuleConflict {
                        rule_a: rule_a.name.clone(),
                        rule_b: rule_b.name.clone(),
                        reason: format!(
                            "Both rules can match simultaneously but route to different toolchains ({} vs {})",
                            rule_a.toolchain, rule_b.toolchain
                        ),
                        resolution: "Adjust priorities or make conditions mutually exclusive".to_string(),
                    });
                }
            }
        }

        if conflicts.is_empty() {
            Ok(ProofReceipt::new(
                Formula::top(),
                vec![ProofStep {
                    step_num: 1,
                    depth: 0,
                    formula: Formula::top(),
                    justification: Justification::Hypothesis,
                    premises: vec![],
                    explanation: Some("No conflicting rules found".to_string()),
                }],
            ))
        } else {
            Err(conflicts)
        }
    }

    /// Find the matching rule for a given issue state
    pub fn match_rule(&self, issue_state: &IssueState) -> Option<&RoutingRule> {
        // Sort by priority (descending) and find first match
        let mut sorted_rules: Vec<_> = self.rules.iter().collect();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        sorted_rules
            .into_iter()
            .find(|rule| evaluate_condition(&rule.condition, issue_state))
    }
}

/// Gap in routing completeness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletenessGap {
    /// Issue type without coverage
    pub issue_type: String,
    /// Suggested fix
    pub suggestion: String,
}

/// Conflict between routing rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConflict {
    /// First conflicting rule
    pub rule_a: String,
    /// Second conflicting rule
    pub rule_b: String,
    /// Reason for conflict
    pub reason: String,
    /// Suggested resolution
    pub resolution: String,
}

/// Issue state for routing decisions
#[derive(Debug, Clone, Default)]
pub struct IssueState {
    /// Active atoms (true propositions)
    pub atoms: std::collections::HashSet<String>,
    /// Risk level (0.0 - 1.0)
    pub risk: f64,
    /// Size estimate
    pub size: String,
    /// Tags
    pub tags: Vec<String>,
}

impl IssueState {
    /// Create new issue state
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an atom as true
    pub fn set_atom(&mut self, atom: impl Into<String>) {
        self.atoms.insert(atom.into());
    }

    /// Check if an atom is true
    pub fn has_atom(&self, atom: &str) -> bool {
        self.atoms.contains(atom)
    }

    /// Set risk level
    pub fn with_risk(mut self, risk: f64) -> Self {
        self.risk = risk.clamp(0.0, 1.0);
        self
    }

    /// Set size
    pub fn with_size(mut self, size: impl Into<String>) -> Self {
        self.size = size.into();
        self
    }

    /// Add tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Check if a condition formula covers a specific atom
fn condition_covers_atom(condition: &Formula, atom: &str) -> bool {
    match condition {
        Formula::Atom(name) => name == atom,
        Formula::Top => true,
        Formula::Bottom => false,
        Formula::Not(inner) => !condition_covers_atom(inner, atom),
        Formula::And(l, r) => condition_covers_atom(l, atom) && condition_covers_atom(r, atom),
        Formula::Or(l, r) => condition_covers_atom(l, atom) || condition_covers_atom(r, atom),
        Formula::Implies(_, r) => condition_covers_atom(r, atom),
        _ => false, // Modal/temporal operators need world semantics
    }
}

/// Check if two conditions can be true simultaneously
fn conditions_can_overlap(a: &Formula, b: &Formula) -> bool {
    // Simplified check - in reality would use SAT solver
    // For now, assume overlap unless explicitly contradictory
    match (a, b) {
        (Formula::Atom(x), Formula::Not(inner)) => {
            if let Formula::Atom(y) = inner.as_ref() {
                x != y
            } else {
                true
            }
        }
        (Formula::Not(inner), Formula::Atom(y)) => {
            if let Formula::Atom(x) = inner.as_ref() {
                x != y
            } else {
                true
            }
        }
        (Formula::Bottom, _) | (_, Formula::Bottom) => false,
        _ => true, // Assume possible overlap
    }
}

/// Evaluate a condition against issue state
fn evaluate_condition(condition: &Formula, state: &IssueState) -> bool {
    match condition {
        Formula::Atom(name) => state.has_atom(name),
        Formula::Top => true,
        Formula::Bottom => false,
        Formula::Not(inner) => !evaluate_condition(inner, state),
        Formula::And(l, r) => evaluate_condition(l, state) && evaluate_condition(r, state),
        Formula::Or(l, r) => evaluate_condition(l, state) || evaluate_condition(r, state),
        Formula::Implies(l, r) => !evaluate_condition(l, state) || evaluate_condition(r, state),
        Formula::Iff(l, r) => evaluate_condition(l, state) == evaluate_condition(r, state),
        _ => false, // Modal/temporal need more context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_rule_creation() {
        let rule = RoutingRule::new("high_risk_code", Formula::atom("is_code_change"), "claude")
            .with_speculation(true, 0.8)
            .with_priority(10);

        assert_eq!(rule.name, "high_risk_code");
        assert_eq!(rule.toolchain, "claude");
        assert!(rule.speculate);
        assert_eq!(rule.confidence, 0.8);
        assert_eq!(rule.priority, 10);
    }

    #[test]
    fn test_routing_spec_completeness() {
        let mut spec = RoutingSpec::new("codex").with_atoms(vec![
            "is_bug".to_string(),
            "is_feature".to_string(),
            "is_refactor".to_string(),
        ]);

        // Add rules for bug and feature, but not refactor
        spec.add_rule(RoutingRule::new(
            "bug_fix",
            Formula::atom("is_bug"),
            "claude",
        ));
        spec.add_rule(RoutingRule::new(
            "new_feature",
            Formula::atom("is_feature"),
            "codex",
        ));

        let result = spec.verify_completeness();
        assert!(result.is_err());

        let gaps = match result {
            Ok(_) => panic!("expected completeness verification to report gaps"),
            Err(gaps) => gaps,
        };
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].issue_type, "is_refactor");
    }

    #[test]
    fn test_routing_spec_consistency() {
        let mut spec = RoutingSpec::new("codex");

        // Add conflicting rules (same priority, overlapping conditions)
        spec.add_rule(
            RoutingRule::new("rule_a", Formula::atom("is_code"), "claude").with_priority(5),
        );
        spec.add_rule(
            RoutingRule::new("rule_b", Formula::atom("is_code"), "codex").with_priority(5),
        );

        let result = spec.verify_consistency();
        assert!(result.is_err());

        let conflicts = match result {
            Ok(_) => panic!("expected consistency verification to report conflicts"),
            Err(conflicts) => conflicts,
        };
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn test_routing_match() {
        let mut spec = RoutingSpec::new("codex");

        spec.add_rule(
            RoutingRule::new("high_priority", Formula::atom("is_urgent"), "claude")
                .with_priority(10),
        );
        spec.add_rule(
            RoutingRule::new("normal", Formula::atom("is_code"), "codex").with_priority(1),
        );

        let mut state = IssueState::new();
        state.set_atom("is_code");
        state.set_atom("is_urgent");

        // Should match high priority rule
        let matched = spec.match_rule(&state);
        assert!(matched.is_some());
        match matched {
            Some(rule) => assert_eq!(rule.name, "high_priority"),
            None => panic!("expected high priority rule to match"),
        }
    }
}
