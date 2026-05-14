//! Integration tests that load built-in ClawdStrike rulesets and verify their
//! policy reports through the public verifier API.

use clawdstrike::policy::{GuardConfigs, RuleSet};
use clawdstrike_logos::logos_ffi::AgentId;
use clawdstrike_logos::verifier::{PolicyVerifier, VerificationBackend};

fn agent() -> AgentId {
    AgentId::new("integration-test-agent")
}

fn preferred_verifier() -> PolicyVerifier {
    #[cfg(feature = "z3")]
    {
        PolicyVerifier::with_z3()
    }

    #[cfg(not(feature = "z3"))]
    {
        PolicyVerifier::new()
    }
}

fn load_ruleset(name: &str) -> RuleSet {
    match RuleSet::by_name(name) {
        Ok(Some(ruleset)) => ruleset,
        Ok(None) => panic!("no such ruleset: {name}"),
        Err(error) => panic!("failed to load ruleset '{name}': {error}"),
    }
}

fn verify_builtin(name: &str) {
    let ruleset = load_ruleset(name);
    let report = preferred_verifier().verify_policy(&ruleset.policy, agent());

    assert!(
        report.consistency.outcome.is_pass(),
        "ruleset '{name}' failed consistency: {:?}",
        report.consistency
    );
    assert!(
        report.completeness.outcome.is_pass(),
        "ruleset '{name}' failed completeness: {:?}",
        report.completeness
    );
    assert!(
        report.formula_count > 0,
        "ruleset '{name}' compiled to 0 formulas"
    );
    assert!(
        report.atom_count > 0,
        "ruleset '{name}' compiled to 0 atoms"
    );

    #[cfg(feature = "z3")]
    assert_eq!(report.backend, VerificationBackend::Z3);
    #[cfg(not(feature = "z3"))]
    assert_eq!(report.backend, VerificationBackend::FormulaInspection);
}

#[test]
fn verify_default_ruleset() {
    verify_builtin("default");
}

#[test]
fn verify_strict_ruleset() {
    verify_builtin("strict");
}

#[test]
fn verify_ai_agent_ruleset() {
    verify_builtin("ai-agent");
}

#[test]
fn verify_permissive_ruleset() {
    verify_builtin("permissive");
}

#[test]
fn verify_self_inheritance_for_default_ruleset() {
    let ruleset = load_ruleset("default");
    let report =
        preferred_verifier().verify_policy_with_parent(&ruleset.policy, &ruleset.policy, agent());
    assert!(
        report.inheritance.outcome.is_pass(),
        "self-inheritance should pass: {:?}",
        report.inheritance
    );
}

#[test]
fn strict_forbidden_path_superset_preserves_default_policy() {
    let default_ruleset = load_ruleset("default");
    let strict_ruleset = load_ruleset("strict");

    let parent = clawdstrike::policy::Policy {
        guards: GuardConfigs {
            forbidden_path: default_ruleset.policy.guards.forbidden_path.clone(),
            ..GuardConfigs::default()
        },
        ..clawdstrike::policy::Policy::default()
    };
    let merged = clawdstrike::policy::Policy {
        guards: GuardConfigs {
            forbidden_path: strict_ruleset.policy.guards.forbidden_path.clone(),
            ..GuardConfigs::default()
        },
        ..clawdstrike::policy::Policy::default()
    };

    let report = preferred_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert!(
        report.inheritance.outcome.is_pass(),
        "strict forbidden_path policy should not weaken default: {:?}",
        report.inheritance
    );
}

#[test]
fn receipt_metadata_uses_backend_field() {
    let ruleset = load_ruleset("default");
    let report = preferred_verifier().verify_policy(&ruleset.policy, agent());

    let receipt = hush_core::receipt::Receipt::new(
        hush_core::hashing::Hash::zero(),
        hush_core::receipt::Verdict::pass(),
    );
    let enriched = clawdstrike_logos::verifier::enrich_receipt(receipt, &report);
    let Some(metadata) = enriched.metadata else {
        panic!("verification metadata missing");
    };

    assert!(metadata["verification"]["backend"].is_string());
    assert!(metadata["verification"]["consistency"].is_string());
    assert!(metadata["verification"]["completeness"].is_string());
    assert!(metadata["verification"]["attestation_level"].is_number());
    assert!(metadata["verification"]["properties_checked"].is_array());
}
