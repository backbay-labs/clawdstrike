//! Policy verification via formula inspection and optional Z3 checking.
//!
//! The formula-only API intentionally stays lightweight and conservative.
//! Policy-aware verification goes further by using guard semantics for
//! inheritance checks, because compiled formulas alone do not carry enough
//! information to model guard-specific override behavior soundly.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Once, OnceLock};
use std::time::Instant;

use clawdstrike::guards::{
    EgressAllowlistConfig, ForbiddenPathConfig, ForbiddenPathGuard, McpDefaultAction,
    McpToolConfig, McpToolGuard, PathAllowlistConfig, PathAllowlistGuard, ShellCommandConfig,
};
use clawdstrike::policy::{LocalPolicyResolver, Policy, PolicyLocation, PolicyResolver};
use glob::Pattern;
use hush_proxy::policy::{DomainPolicy, PolicyAction};
#[cfg(feature = "z3")]
use logos_ffi::ProofResult;
use logos_ffi::{AgentId, Formula};
#[cfg(feature = "z3")]
use logos_z3::Z3Checker;
use regex::Regex;
use regex_syntax::hir::{Class, Hir, HirKind, Look};
use regex_syntax::Parser;
use serde::{Deserialize, Serialize};

use crate::compiler::{DefaultPolicyCompiler, PolicyCompiler};

mod report;
mod verifier_core;
mod inheritance;
mod witness;
mod load_time;

// Public surface: re-exported so external callers keep using
// `clawdstrike_logos::verifier::<Item>` regardless of the submodule layout.
pub use load_time::{
    enrich_receipt, install_clawdstrike_policy_load_verifier, verify_policy_at_load_time,
    verify_policy_at_load_time_with_resolver, LoadTimeVerificationResult, VerificationCache,
};
pub use report::{
    AttestationLevel, CheckOutcome, CompletenessResult, Conflict, ConsistencyResult,
    InheritanceResult, VerificationBackend, VerificationReport, WeakenedProhibition,
    DEFAULT_EXPECTED_ACTION_TYPES,
};
pub use verifier_core::PolicyVerifier;

// Internal cross-module resolution: each submodule reaches the others' private
// helpers through these globs + its own `use super::*`.
pub(crate) use inheritance::*;
// `load_time`'s pub(crate) helpers (e.g. `verify_policy_at_load_time_with_parent`)
// are reached only from `mod tests { use super::* }`; nothing in a non-test build
// calls into them across modules, so the glob is unused without `cfg(test)`.
#[allow(unused_imports)]
pub(crate) use load_time::*;
pub(crate) use report::*;
pub(crate) use verifier_core::*;
pub(crate) use witness::*;

#[cfg(test)]
fn expected_action_types_for_policy_set(policy: &Policy) -> BTreeSet<String> {
    expected_action_types_for_policy(policy)
        .into_iter()
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use crate::atoms::ActionKind;
    use clawdstrike::guards::{
        EgressAllowlistConfig, ForbiddenPathConfig, McpToolConfig, PathAllowlistConfig,
        PromptInjectionConfig, SecretLeakConfig, ShellCommandConfig,
    };
    use clawdstrike::policy::{GuardConfigs, Policy, RuleSet, VerificationSettings};
    use hush_proxy::policy::PolicyAction;
    use logos_ffi::AgentId;

    fn agent() -> AgentId {
        AgentId::new("test-agent")
    }

    fn formula_verifier() -> PolicyVerifier {
        PolicyVerifier::new()
    }

    fn simple_forbidden_path(path: &str) -> ForbiddenPathConfig {
        ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec![path.to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }

    #[test]
    fn consistent_when_no_overlap() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("egress(api.openai.com)")),
        ];
        let result = formula_verifier().check_consistency(&formulas);
        assert!(result.outcome.is_pass());
        assert_eq!(result.conflict_count, 0);
    }

    #[test]
    fn obligation_and_prohibition_conflict_detected() {
        let formulas = vec![
            Formula::obligation(agent(), Formula::atom("exec(rm -rf /)")),
            Formula::prohibition(agent(), Formula::atom("exec(rm -rf /)")),
        ];
        let result = formula_verifier()
            .with_expected_action_types(vec!["exec".to_string()])
            .verify(&formulas, None);
        assert_eq!(result.consistency.outcome, CheckOutcome::Fail);
        assert!(result
            .consistency
            .conflicts
            .iter()
            .any(|conflict| conflict.atom == "exec(rm -rf /)"));
    }

    #[test]
    fn completeness_with_custom_expected_types() {
        let formulas = vec![Formula::prohibition(
            agent(),
            Formula::atom("access(/etc/shadow)"),
        )];
        let result = formula_verifier()
            .with_expected_action_types(vec!["access".to_string()])
            .check_completeness(&formulas);
        assert!(result.outcome.is_pass());
        assert_eq!(result.covered, vec!["access".to_string()]);
    }

    #[test]
    fn inheritance_is_skipped_for_formula_only_api() {
        let formulas = vec![Formula::prohibition(
            agent(),
            Formula::atom("access(/etc/shadow)"),
        )];
        let report = formula_verifier()
            .with_expected_action_types(vec!["access".to_string()])
            .verify(&formulas, None);
        assert_eq!(report.inheritance.outcome, CheckOutcome::Skipped);
        assert_eq!(report.backend, VerificationBackend::FormulaInspection);
        assert_eq!(report.attestation_level, AttestationLevel::FormulaVerified);
    }

    #[test]
    fn dynamic_policy_completeness_only_requires_configured_guards() {
        let mut policy = Policy::default();
        policy.guards = GuardConfigs {
            forbidden_path: Some(simple_forbidden_path("/etc/shadow")),
            egress_allowlist: Some(EgressAllowlistConfig {
                enabled: true,
                allow: vec!["api.openai.com".to_string()],
                block: vec![],
                default_action: None,
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            }),
            ..GuardConfigs::default()
        };

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.completeness.outcome.is_pass(), "{report:?}");
        assert_eq!(report.completeness.covered, vec!["access", "egress"]);
        assert!(report.completeness.missing.is_empty());
    }

    #[test]
    fn configured_action_types_are_derived_from_enabled_guards() {
        let mut policy = Policy::default();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.openai.com".to_string()],
            block: vec![],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        assert_eq!(
            expected_action_types_for_policy_set(&policy),
            BTreeSet::from(["egress".to_string()])
        );
    }

    #[test]
    fn shell_forbidden_path_enforcement_requires_exec_coverage() {
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
        policy.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![],
            enforce_forbidden_paths: true,
        });

        assert_eq!(
            expected_action_types_for_policy_set(&policy),
            BTreeSet::from(["access".to_string(), "exec".to_string()])
        );

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.completeness.outcome.is_pass(), "{report:?}");
        assert!(report
            .completeness
            .covered
            .iter()
            .any(|kind| kind == "exec"));
    }

    #[test]
    fn runtime_only_guards_contribute_custom_action_coverage() {
        let mut policy = Policy::default();
        policy.guards.secret_leak = Some(SecretLeakConfig::default());
        policy.guards.prompt_injection = Some(PromptInjectionConfig::default());

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.formula_count > 0, "{report:?}");
        assert!(report
            .completeness
            .covered
            .iter()
            .any(|action_type| action_type == "custom"));
        assert!(report.completeness.missing.is_empty(), "{report:?}");
    }

    #[test]
    fn policy_custom_guards_downgrade_attestation_to_heuristic() {
        let mut policy = Policy::default();
        policy
            .custom_guards
            .push(clawdstrike::policy::PolicyCustomGuardSpec {
                id: "demo-guard".to_string(),
                enabled: true,
                config: serde_json::json!({}),
            });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.completeness.outcome, CheckOutcome::Fail);
        assert!(report
            .completeness
            .missing
            .iter()
            .any(|kind| kind == "unsupported_policy_custom_guards"));
        assert_eq!(report.attestation_level, AttestationLevel::Heuristic);
    }

    #[test]
    fn plugin_custom_guards_downgrade_attestation_to_heuristic() {
        let mut policy = Policy::default();
        policy
            .guards
            .custom
            .push(clawdstrike::policy::CustomGuardSpec {
                package: "demo-plugin".to_string(),
                registry: None,
                version: None,
                enabled: true,
                config: serde_json::json!({}),
                async_config: None,
            });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.completeness.outcome, CheckOutcome::Fail);
        assert!(report
            .completeness
            .missing
            .iter()
            .any(|kind| kind == "unsupported_plugin_custom_guards"));
        assert_eq!(report.attestation_level, AttestationLevel::Heuristic);
    }

    #[test]
    fn contradictory_egress_policy_detected() {
        let mut policy = Policy::default();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["evil.example.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.consistency.outcome, CheckOutcome::Fail);
    }

    #[test]
    fn mcp_allow_and_block_same_tool_conflict() {
        let mut policy = Policy::default();
        policy.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec!["shell_exec".to_string()],
            block: vec!["shell_exec".to_string()],
            require_confirmation: vec![],
            default_action: None,
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.consistency.outcome, CheckOutcome::Fail);
    }

    #[test]
    fn sound_inheritance_passes_for_stricter_child_policy() {
        let mut parent = Policy::default();
        parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let mut merged = parent.clone();
        merged.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert!(report.inheritance.outcome.is_pass(), "{report:?}");
        assert!(report.all_pass());
    }

    #[test]
    fn inheritance_uses_source_child_without_false_failure() {
        let mut parent = Policy::default();
        parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let mut child = Policy::default();
        child.extends = Some("parent.yaml".to_string());

        let effective = parent.merge(&child);
        let report = formula_verifier().verify_policy_with_parent_and_source(
            &parent,
            &child,
            &effective,
            agent(),
        );
        assert!(report.inheritance.outcome.is_pass(), "{report:?}");
    }

    #[test]
    fn origin_enclaves_ruleset_reports_expected_egress_widening() {
        let (parent_yaml, _) = RuleSet::yaml_by_name("default").unwrap();
        let parent = Policy::from_yaml(parent_yaml).unwrap();

        let (child_yaml, _) = RuleSet::yaml_by_name("origin-enclaves-example").unwrap();
        let child = Policy::from_yaml(child_yaml).unwrap();
        let effective = parent.merge(&child);

        let report = formula_verifier().verify_policy_with_parent_and_source(
            &parent,
            &child,
            &effective,
            agent(),
        );

        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "egress(x.internal.corp)"));
    }

    #[test]
    fn build_policy_report_preserves_caller_timing() {
        let report = build_policy_report(
            &[Formula::prohibition(
                agent(),
                Formula::atom("access(/etc/shadow)"),
            )],
            None,
            ConsistencyResult {
                outcome: CheckOutcome::Pass,
                conflict_count: 0,
                conflicts: Vec::new(),
            },
            CompletenessResult {
                outcome: CheckOutcome::Pass,
                covered: vec!["access".to_string()],
                missing: Vec::new(),
            },
            VerificationBackend::FormulaInspection,
            37,
        );

        assert_eq!(report.verification_time_ms, 37);
    }

    #[test]
    fn forbidden_path_exception_weakening_is_detected_semantically() {
        let mut parent = Policy::default();
        parent.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/.env".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/.env".to_string()]),
            exceptions: vec!["/tmp/project/.env".to_string()],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "access(/tmp/project/.env)"));
    }

    #[test]
    fn path_allowlist_widening_is_detected_semantically() {
        let mut parent = Policy::default();
        parent.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["/workspace/project/**".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["/workspace/**".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "access(/workspace/x)"));
    }

    #[test]
    fn path_allowlist_widening_uses_multiple_representatives() {
        let mut parent = Policy::default();
        parent.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["/workspace/*x*".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["/workspace/*".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "access(/workspace/a)"));
    }

    #[test]
    fn shortest_common_supersequence_does_not_duplicate_shared_suffixes() {
        let left = vec!["a".to_string(), "b".to_string()];
        let right = vec!["c".to_string(), "b".to_string()];

        assert_eq!(
            shortest_common_supersequence(&left, &right),
            vec!["a".to_string(), "c".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn egress_allow_override_is_detected_semantically() {
        let mut parent = Policy::default();
        parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec!["*.internal".to_string()],
            default_action: Some(PolicyAction::Allow),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["db.internal".to_string()],
            block: vec![],
            default_action: Some(PolicyAction::Allow),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "egress(db.internal)"));
    }

    #[test]
    fn egress_default_block_without_child_guard_is_detected() {
        let mut parent = Policy::default();
        parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let child = Policy::default();
        let report = formula_verifier().verify_policy_with_parent(&parent, &child, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "egress(clawdstrike-inheritance-check.invalid)"));
    }

    #[test]
    fn egress_modifier_weakening_uses_effective_patterns() {
        let mut parent = Policy::default();
        parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Allow),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec!["*.internal".to_string()],
            remove_block: vec![],
        });

        let mut merged = Policy::default();
        merged.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Allow),
            additional_allow: vec!["db.internal".to_string()],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec!["*.internal".to_string()],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "egress(db.internal)"));
    }

    #[test]
    fn mcp_allow_override_is_detected_semantically() {
        let mut parent = Policy::default();
        parent.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec!["shell_exec".to_string()],
            require_confirmation: vec![],
            default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec!["shell_exec".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "mcp(shell_exec)"));
    }

    #[test]
    fn mcp_max_args_size_weakening_is_detected() {
        let mut parent = Policy::default();
        parent.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
            max_args_size: Some(32),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let mut merged = parent.clone();
        merged.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
            max_args_size: Some(128),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "mcp(safe_tool,args_size=33)"));
    }

    #[test]
    fn dropped_shell_command_guard_is_detected_semantically() {
        let mut parent = Policy::default();
        parent.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: true,
        });

        let merged = Policy::default();
        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "exec(rm -rf /)"));
    }

    #[test]
    fn shell_command_path_enforcement_drop_is_detected() {
        let mut parent = Policy::default();
        parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
        parent.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: true,
        });

        let mut merged = parent.clone();
        merged.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: false,
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "exec(touches /etc/shadow)"));
    }

    #[test]
    fn shell_command_regex_semantics_allow_stricter_replacement() {
        let mut parent = Policy::default();
        parent.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![
                r"(?i)\bcurl\s+https://example\.invalid/install\.sh\s+\|\s+bash\b".to_string(),
            ],
            enforce_forbidden_paths: false,
        });

        let mut merged = parent.clone();
        merged.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![r"(?i)\bcurl\s+\S+\s+\|\s+bash\b".to_string()],
            enforce_forbidden_paths: false,
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert!(report.inheritance.outcome.is_pass(), "{report:?}");
    }

    #[test]
    fn shell_command_default_forbidden_paths_are_checked_in_inheritance() {
        let mut parent = Policy::default();
        parent.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: true,
        });

        let mut merged = parent.clone();
        merged.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: false,
        });

        let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
        assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
        assert!(report
            .inheritance
            .weakened
            .iter()
            .any(|item| item.atom == "exec(touches /etc/shadow)"));
    }

    #[test]
    fn brace_alternatives_are_fully_consumed_when_generating_tokens() {
        assert_eq!(representative_token("{alice,bob}.txt"), "alice.txt");
        assert_eq!(literal_segment("{alice,bob}.txt"), "alice.txt");
    }

    #[test]
    fn dot_prefixed_segments_stay_valid_representatives() {
        let wildcard_dot = literal_segment("*.env");
        let wildcard_qmark = literal_segment("?.config");
        assert_eq!(wildcard_dot, ".env");
        assert_eq!(wildcard_qmark, "x.config");
        assert!(Pattern::new("*.env")
            .expect("valid glob")
            .matches(&wildcard_dot));
        assert!(Pattern::new("?.config")
            .expect("valid glob")
            .matches(&wildcard_qmark));
        assert_eq!(literal_segment(".env"), ".env");
    }

    #[test]
    fn negated_char_class_probe_still_matches_pattern() {
        let probe = representative_token("[!0]");
        assert_ne!(probe, "0");
        assert!(Pattern::new("[!0]").expect("valid glob").matches(&probe));
    }

    #[test]
    fn negated_char_class_can_exclude_closing_bracket() {
        let probe = representative_token("[!]]");
        assert_ne!(probe, "]");
        assert!(Pattern::new("[!]]").expect("valid glob").matches(&probe));
    }

    #[test]
    fn negated_char_class_witness_finds_real_overlap() {
        let witness =
            path_intersection_witness("/tmp/[!0]", "/tmp/*").expect("expected overlapping witness");
        assert!(path_pattern_matches("/tmp/[!0]", &witness));
        assert!(path_pattern_matches("/tmp/*", &witness));
    }

    #[test]
    fn literal_suffix_token_keeps_escaped_meta_literals() {
        assert_eq!(literal_suffix_token(r"abc\*def"), "abc*def");
        assert_eq!(literal_suffix_token(r"abc\?def"), "abc?def");
    }

    #[test]
    fn regex_repetition_samples_respect_positive_minimum() {
        assert_eq!(regex_hir_samples_from_pattern("a{4}", 1), vec!["aaaa"]);
    }

    #[test]
    fn regex_repetition_samples_do_not_emit_empty_for_nonempty_plus_class() {
        let compiled = Regex::new(r"\s+").expect("valid regex");
        let samples = regex_hir_samples_from_pattern(r"\s+", 16);
        assert!(!samples.is_empty());
        assert!(samples.iter().all(|sample| !sample.is_empty()));
        assert!(samples.iter().all(|sample| compiled.is_match(sample)));
    }

    #[test]
    fn default_mcp_probe_returns_unused_fallback_when_probe_space_is_exhausted() {
        let mut cfg = McpToolConfig {
            enabled: true,
            allow: vec!["__clawdstrike_inheritance_probe__".to_string()],
            block: Vec::new(),
            require_confirmation: Vec::new(),
            default_action: None,
            max_args_size: None,
            additional_allow: Vec::new(),
            remove_allow: Vec::new(),
            additional_block: Vec::new(),
            remove_block: Vec::new(),
        };
        cfg.allow
            .extend((0..32).map(|idx| format!("__clawdstrike_inheritance_probe_{idx}__")));

        let probe = default_mcp_probe(&cfg, None);
        assert!(!probe.is_empty());
        assert!(!cfg.allow.contains(&probe));
        assert!(!cfg.block.contains(&probe));
        assert!(!cfg.require_confirmation.contains(&probe));
    }

    #[test]
    fn receipt_metadata_uses_honest_backend_fields() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("egress(api.openai.com)")),
        ];
        let report = formula_verifier()
            .with_expected_action_types(vec!["access".to_string(), "egress".to_string()])
            .verify(&formulas, None);
        let receipt = hush_core::receipt::Receipt::new(
            hush_core::hashing::Hash::zero(),
            hush_core::receipt::Verdict::pass(),
        );
        let enriched = enrich_receipt(receipt, &report);
        let metadata = enriched.metadata.expect("verification metadata");

        assert_eq!(metadata["verification"]["backend"], "formula_inspection");
        assert_eq!(metadata["verification"]["checks_passed"], true);
        assert_eq!(metadata["verification"]["consistency"], "pass");
        assert_eq!(metadata["verification"]["completeness"], "pass");
        assert_eq!(metadata["verification"]["inheritance_sound"], "skipped");
        assert_eq!(metadata["verification"]["attestation_level"], 1);
        assert_eq!(
            metadata["verification"]["attestation_level_name"],
            "formula_verified"
        );
    }

    #[test]
    fn metadata_reports_failure_honestly() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("access(/etc/shadow)")),
        ];
        let report = formula_verifier()
            .with_expected_action_types(vec![])
            .verify(&formulas, None);
        let metadata = report.to_receipt_metadata();
        assert_eq!(metadata["verification"]["backend"], "formula_inspection");
        assert_eq!(metadata["verification"]["checks_passed"], false);
        assert_eq!(metadata["verification"]["consistency"], "fail");
        assert_eq!(metadata["verification"]["attestation_level"], 0);
        assert_eq!(
            metadata["verification"]["attestation_level_name"],
            "heuristic"
        );
    }

    #[test]
    fn attestation_level_roundtrip_and_ordering() {
        for level_u8 in 0..=4 {
            let level = AttestationLevel::from_u8(level_u8).unwrap();
            assert_eq!(level.as_u8(), level_u8);
        }
        assert!(AttestationLevel::from_u8(5).is_none());
        assert!(AttestationLevel::Heuristic < AttestationLevel::FormulaVerified);
        assert!(AttestationLevel::FormulaVerified < AttestationLevel::Z3Verified);
        assert!(AttestationLevel::Z3Verified < AttestationLevel::LeanProved);
        assert!(AttestationLevel::LeanProved < AttestationLevel::ImplementationVerified);
    }

    #[test]
    fn attestation_level_names_and_display_are_honest() {
        assert_eq!(AttestationLevel::Heuristic.name(), "heuristic");
        assert_eq!(AttestationLevel::FormulaVerified.name(), "formula_verified");
        assert_eq!(AttestationLevel::Z3Verified.name(), "z3_verified");
        assert_eq!(
            format!("{}", AttestationLevel::FormulaVerified),
            "Level 1 (formula_verified)"
        );
        assert_eq!(
            format!("{}", AttestationLevel::Z3Verified),
            "Level 2 (z3_verified)"
        );
    }

    #[test]
    fn action_kind_roundtrip_still_works() {
        assert_eq!(ActionKind::all().len(), 7);
        assert_eq!(ActionKind::core().len(), 4);
        for kind in ActionKind::all() {
            let prefix = format!("{kind}");
            assert_eq!(ActionKind::from_prefix(&prefix), Some(kind));
        }
        assert_eq!(ActionKind::from_prefix("unknown"), None);
    }

    #[test]
    fn load_time_skip_when_not_enabled() {
        let policy = Policy::default();
        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache).unwrap();
        assert!(result.report.is_none());
        assert!(result.error.is_none());
        assert!(!result.cache_hit);
    }

    #[test]
    fn load_time_runs_when_enabled() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: false,
        });
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache).unwrap();
        assert!(result.report.is_some());
        assert!(!result.cache_hit);
    }

    #[test]
    fn load_time_strict_blocks_on_failure() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: true,
            cache: false,
        });
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["evil.example.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache);
        assert!(result.is_err());
    }

    #[test]
    fn load_time_strict_fails_closed_without_inheritance_context() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: true,
            cache: false,
        });
        policy.extends = Some("parent.yaml".to_string());

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache);

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap_or_default()
            .contains("missing source location/resolver context"));
    }

    #[test]
    fn load_time_with_resolver_enforces_inheritance_soundness() {
        let parent = Policy::from_yaml(
            r#"
version: "1.1.0"
name: "parent"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("parse parent");

        let source_policy = Policy {
            version: "1.1.0".to_string(),
            name: "child".to_string(),
            extends: Some("parent.yaml".to_string()),
            settings: clawdstrike::policy::PolicySettings {
                verification: Some(VerificationSettings {
                    enabled: true,
                    strict: true,
                    cache: false,
                }),
                ..Default::default()
            },
            guards: GuardConfigs {
                forbidden_path: Some(ForbiddenPathConfig {
                    enabled: true,
                    patterns: None,
                    exceptions: Vec::new(),
                    additional_patterns: Vec::new(),
                    remove_patterns: vec!["/etc/shadow".to_string()],
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let effective_policy = parent.merge(&source_policy);

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent,
            &cache,
        );

        let err = result.expect_err("weakened inheritance should fail strict verification");
        assert!(err.contains("inheritance"));
    }

    #[test]
    fn strict_extends_load_verifies_invalid_ancestor_transitively() {
        install_clawdstrike_policy_load_verifier();

        let dir = std::env::temp_dir().join(format!(
            "clawdstrike_logos_verifier_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let grandparent = dir.join("grandparent.yaml");
        let parent = dir.join("parent.yaml");
        let child = dir.join("child.yaml");

        std::fs::write(
            &grandparent,
            r#"
version: "1.5.0"
name: "grandparent"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write grandparent");

        std::fs::write(
            &parent,
            r#"
version: "1.5.0"
name: "parent"
extends: "grandparent.yaml"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    remove_patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write parent");

        std::fs::write(
            &child,
            r#"
version: "1.5.0"
name: "child"
extends: "parent.yaml"
settings:
  verification:
    enabled: true
    strict: true
"#,
        )
        .expect("write child");

        let child_yaml = std::fs::read_to_string(&child).expect("read child");
        let err = Policy::from_yaml_with_extends(&child_yaml, Some(child.as_path()))
            .expect_err("invalid strict parent should fail transitively");
        assert!(err.to_string().contains("inheritance"));
    }

    #[test]
    fn load_time_caching_works() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: true,
        });
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let cache = VerificationCache::new();
        let first = verify_policy_at_load_time(&policy, &cache).unwrap();
        let second = verify_policy_at_load_time(&policy, &cache).unwrap();

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cached_non_strict_failure_preserves_error_details() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: true,
        });
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["evil.example.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let cache = VerificationCache::new();
        let first = verify_policy_at_load_time(&policy, &cache).expect("first verification");
        let second = verify_policy_at_load_time(&policy, &cache).expect("second verification");

        assert!(!first.cache_hit);
        assert!(first.error.is_some());
        assert!(second.cache_hit);
        assert!(second.error.is_some());
    }

    #[test]
    fn cache_eviction_keeps_bounded_size() {
        let cache = VerificationCache::with_capacity_limit(2);
        let report = formula_verifier().verify(&[], None);

        cache.insert("one".to_string(), report.clone());
        cache.insert("two".to_string(), report.clone());
        cache.insert("three".to_string(), report);

        assert_eq!(cache.len(), 2);
        assert!(cache.get("one").is_none());
        assert!(cache.get("two").is_some());
        assert!(cache.get("three").is_some());
    }

    #[test]
    fn resolver_style_cache_keys_include_parent_policy_content() {
        let mut parent_with_guard = Policy::default();
        parent_with_guard.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let parent_without_guard = Policy::default();

        let source_policy = Policy {
            version: "1.5.0".to_string(),
            name: "child".to_string(),
            extends: Some("parent.yaml".to_string()),
            merge_strategy: clawdstrike::policy::MergeStrategy::Replace,
            settings: clawdstrike::policy::PolicySettings {
                verification: Some(VerificationSettings {
                    enabled: true,
                    strict: false,
                    cache: true,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let effective_policy = parent_with_guard.merge(&source_policy);
        let cache = VerificationCache::new();

        let first = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent_with_guard,
            &cache,
        )
        .expect("first verification");
        assert!(!first.cache_hit);
        assert!(first.error.is_some());

        let second = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent_without_guard,
            &cache,
        )
        .expect("second verification");
        assert!(!second.cache_hit);
        assert!(second.error.is_none());
        assert_eq!(cache.len(), 2);
    }

    #[cfg(feature = "z3")]
    #[test]
    fn z3_completeness_counterexample_marks_report_failed() {
        let inspected = CompletenessResult {
            outcome: CheckOutcome::Pass,
            covered: vec!["access".to_string()],
            missing: Vec::new(),
        };
        let counterexample = logos_ffi::Counterexample::simple(
            Formula::Top,
            vec![logos_ffi::StateAssignment {
                atom: "access(__missing__)".to_string(),
                world: None,
                time: None,
                value: false,
            }],
        );

        let result = completeness_result_from_z3_counterexample(
            inspected,
            &counterexample,
            &["access".to_string()],
        );

        assert_eq!(result.outcome, CheckOutcome::Fail);
        assert_eq!(result.missing, vec!["access".to_string()]);
        assert!(result.covered.is_empty());
    }

    #[cfg(feature = "z3")]
    #[test]
    fn z3_verifier_reports_real_z3_backend() {
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.openai.com".to_string()],
            block: vec![],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = PolicyVerifier::with_z3().verify_policy(&policy, agent());
        assert_eq!(report.backend, VerificationBackend::Z3);
        assert_eq!(report.attestation_level, AttestationLevel::Z3Verified);
        assert!(report.all_pass());
    }
}
