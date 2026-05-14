#![cfg(feature = "full")]
//! HushSpec fixture conformance tests.
//!
//! These tests load fixtures from the vendored HushSpec snapshot and verify the
//! Clawdstrike HushSpec compiler handles them correctly:
//!
//! - Valid fixtures parse + validate + compile without error.
//! - Invalid fixtures are rejected at parse or validation time.
//! - Merge fixtures produce correct merged output that compiles.
//! - Built-in HushSpec rulesets compile to valid Clawdstrike policies.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use clawdstrike::hushspec_compiler;
use clawdstrike::policy::POLICY_SCHEMA_VERSION;
use std::path::Path;

const HUSHSPEC_SNAPSHOT_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/hushspec");
const FIXTURES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/hushspec/fixtures"
);

fn fixture_path(relative: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(relative)
}

fn read_fixture(relative: &str) -> String {
    let path = fixture_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e))
}

// ===========================================================================
// Valid fixtures should parse, validate, and compile
// ===========================================================================

#[test]
fn compile_valid_minimal() {
    let yaml = read_fixture("core/valid/minimal.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    assert_eq!(policy.version, POLICY_SCHEMA_VERSION);
}

#[test]
fn compile_valid_named() {
    let yaml = read_fixture("core/valid/named.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    assert_eq!(policy.name, "test-policy");
    assert_eq!(
        policy.description,
        "A test policy for conformance validation"
    );
}

#[test]
fn compile_valid_egress_only() {
    let yaml = read_fixture("core/valid/egress-only.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    let egress = policy
        .guards
        .egress_allowlist
        .as_ref()
        .expect("egress guard");
    assert!(egress.allow.contains(&"api.openai.com".to_string()));
    assert!(egress.allow.contains(&"api.anthropic.com".to_string()));
}

#[test]
fn compile_valid_full_rules() {
    let yaml = read_fixture("core/valid/full-rules.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    // All 10 core rule types should be present
    assert!(policy.guards.forbidden_path.is_some(), "forbidden_path");
    assert!(policy.guards.path_allowlist.is_some(), "path_allowlist");
    assert!(policy.guards.egress_allowlist.is_some(), "egress_allowlist");
    assert!(policy.guards.secret_leak.is_some(), "secret_leak");
    assert!(policy.guards.patch_integrity.is_some(), "patch_integrity");
    assert!(policy.guards.shell_command.is_some(), "shell_command");
    assert!(policy.guards.mcp_tool.is_some(), "mcp_tool");
    assert!(policy.guards.computer_use.is_some(), "computer_use");
    assert!(
        policy.guards.remote_desktop_side_channel.is_some(),
        "remote_desktop_side_channel"
    );
    assert!(
        policy.guards.input_injection_capability.is_some(),
        "input_injection_capability"
    );
}

#[test]
fn compile_valid_extends_basic() {
    let yaml = read_fixture("core/valid/extends-basic.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    // extends: "hushspec:default" should become "default" after stripping prefix
    assert_eq!(policy.extends, Some("default".to_string()));
}

#[test]
fn compile_valid_rules_and_extensions() {
    let yaml = read_fixture("core/valid/rules-and-extensions.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    // Rules
    assert!(policy.guards.egress_allowlist.is_some(), "egress");
    assert!(policy.guards.mcp_tool.is_some(), "mcp_tool");
    assert!(policy.guards.forbidden_path.is_some(), "forbidden_path");
    // Detection extension -> guards
    assert!(policy.guards.prompt_injection.is_some(), "prompt_injection");
    assert!(policy.guards.jailbreak.is_some(), "jailbreak");
    // Posture extension
    let posture = policy.posture.as_ref().expect("posture");
    assert_eq!(posture.initial, "standard");
    assert!(posture.states.contains_key("standard"));
    assert!(posture.states.contains_key("restricted"));
    // Origins extension
    let origins = policy.origins.as_ref().expect("origins");
    assert_eq!(origins.profiles.len(), 1);
    assert_eq!(origins.profiles[0].id, "internal");
}

// ===========================================================================
// Posture fixtures
// ===========================================================================

#[test]
fn compile_posture_three_state() {
    let yaml = read_fixture("posture/valid/three-state.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    let posture = policy.posture.as_ref().expect("posture");
    assert_eq!(posture.initial, "standard");
    assert_eq!(posture.states.len(), 3);
    assert!(posture.states.contains_key("restricted"));
    assert!(posture.states.contains_key("standard"));
    assert!(posture.states.contains_key("elevated"));
    assert_eq!(posture.transitions.len(), 5);
}

// ===========================================================================
// Origins fixtures
// ===========================================================================

#[test]
fn compile_origins_multi_profile() {
    let yaml = read_fixture("origins/valid/multi-profile.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    let origins = policy.origins.as_ref().expect("origins");
    assert_eq!(origins.profiles.len(), 4);
    // Verify profile IDs
    let ids: Vec<&str> = origins.profiles.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"incident-room"));
    assert!(ids.contains(&"external-chat"));
    assert!(ids.contains(&"code-review"));
    assert!(ids.contains(&"internal-default"));
}

// ===========================================================================
// Detection fixtures
// ===========================================================================

#[test]
fn compile_detection_full() {
    let yaml = read_fixture("detection/valid/full-detection.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "validation errors: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile");
    assert!(policy.guards.prompt_injection.is_some(), "prompt_injection");
    assert!(policy.guards.jailbreak.is_some(), "jailbreak");
    let pi = policy.guards.prompt_injection.as_ref().unwrap();
    assert!(pi.enabled);
    assert_eq!(pi.max_scan_bytes, 200_000);
    let jb = policy.guards.jailbreak.as_ref().unwrap();
    assert!(jb.enabled);
    assert_eq!(jb.detector.block_threshold, 40);
    assert_eq!(jb.detector.warn_threshold, 15);
}

// ===========================================================================
// Invalid fixtures should fail to parse or validate
// ===========================================================================

#[test]
fn reject_unknown_top_level() {
    let yaml = read_fixture("core/invalid/unknown-top-level.yaml");
    let result = hushspec::HushSpec::parse(&yaml);
    assert!(
        result.is_err(),
        "should reject unknown top-level fields (deny_unknown_fields)"
    );
}

#[test]
fn reject_unknown_rule() {
    let yaml = read_fixture("core/invalid/unknown-rule.yaml");
    let result = hushspec::HushSpec::parse(&yaml);
    assert!(
        result.is_err(),
        "should reject unknown rules (deny_unknown_fields)"
    );
}

#[test]
fn reject_missing_version() {
    let yaml = read_fixture("core/invalid/missing-version.yaml");
    // missing-version.yaml has no `hushspec:` field, so serde should reject it
    let result = hushspec::HushSpec::parse(&yaml);
    assert!(
        result.is_err(),
        "should reject document missing required hushspec field"
    );
}

#[test]
fn reject_bad_severity() {
    let yaml = read_fixture("core/invalid/bad-severity.yaml");
    let result = hushspec::HushSpec::parse(&yaml);
    assert!(result.is_err(), "should reject invalid severity enum value");
}

#[test]
fn reject_bad_default_action() {
    let yaml = read_fixture("core/invalid/bad-default-action.yaml");
    let result = hushspec::HushSpec::parse(&yaml);
    assert!(
        result.is_err(),
        "should reject invalid default action enum value"
    );
}

#[test]
fn reject_duplicate_pattern_names() {
    let yaml = read_fixture("core/invalid/duplicate-pattern-names.yaml");
    // Duplicate keys parse fine in YAML, but validation catches them
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse succeeds (YAML allows duplicates)");
    let validation = hushspec::validate(&spec);
    assert!(
        !validation.is_valid(),
        "should catch duplicate pattern names"
    );
    let has_dup_error = validation.errors.iter().any(|e| {
        matches!(e, hushspec::ValidationError::DuplicatePatternName(name) if name == "duplicate")
    });
    assert!(
        has_dup_error,
        "expected DuplicatePatternName error, got: {:?}",
        validation.errors
    );
}

// -- Posture invalid --

#[test]
fn reject_posture_bad_initial() {
    let yaml = read_fixture("posture/invalid/bad-initial.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        !validation.is_valid(),
        "should reject posture with initial referencing nonexistent state"
    );
}

#[test]
fn reject_posture_timeout_no_after() {
    let yaml = read_fixture("posture/invalid/timeout-no-after.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        !validation.is_valid(),
        "should reject timeout transition without after field"
    );
}

// -- Origins invalid --

#[test]
fn reject_origins_duplicate_ids() {
    let yaml = read_fixture("origins/invalid/duplicate-ids.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        !validation.is_valid(),
        "should reject duplicate origin profile IDs"
    );
}

// -- Detection invalid --

#[test]
fn reject_detection_bad_similarity() {
    let yaml = read_fixture("detection/invalid/bad-similarity.yaml");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse");
    let validation = hushspec::validate(&spec);
    assert!(
        !validation.is_valid(),
        "should reject similarity_threshold > 1.0"
    );
}

// ===========================================================================
// Merge fixtures: merge base + child, then compile the result
// ===========================================================================

#[test]
fn merge_deep_merge_then_compile() {
    let base_yaml = read_fixture("core/merge/base.yaml");
    let child_yaml = read_fixture("core/merge/child-deep-merge.yaml");
    let base = hushspec::HushSpec::parse(&base_yaml).expect("parse base");
    let child = hushspec::HushSpec::parse(&child_yaml).expect("parse child");
    let merged = hushspec::merge(&base, &child);
    let policy = hushspec_compiler::compile(&merged).expect("compile merged");
    // Child egress overrides base (deep merge uses child rule when present)
    let egress = policy.guards.egress_allowlist.as_ref().expect("egress");
    assert!(
        egress.allow.contains(&"c.com".to_string()),
        "child egress should contain c.com"
    );
    // Base forbidden_paths should be preserved (child did not provide forbidden_paths)
    assert!(
        policy.guards.forbidden_path.is_some(),
        "base forbidden_path should survive merge"
    );
    let fp = policy.guards.forbidden_path.as_ref().unwrap();
    let patterns = fp.effective_patterns();
    assert!(patterns.contains(&"**/.ssh/**".to_string()));
    assert!(patterns.contains(&"**/.aws/**".to_string()));
}

#[test]
fn merge_replace_then_compile() {
    let base_yaml = read_fixture("core/merge/base.yaml");
    let child_yaml = read_fixture("core/merge/child-replace.yaml");
    let base = hushspec::HushSpec::parse(&base_yaml).expect("parse base");
    let child = hushspec::HushSpec::parse(&child_yaml).expect("parse child");
    let merged = hushspec::merge(&base, &child);
    let policy = hushspec_compiler::compile(&merged).expect("compile merged");
    // Replace strategy: only child's rules should exist
    assert!(
        policy.guards.egress_allowlist.is_none(),
        "base egress should be gone after replace"
    );
    assert!(
        policy.guards.forbidden_path.is_none(),
        "base forbidden_path should be gone after replace"
    );
    assert!(
        policy.guards.mcp_tool.is_some(),
        "child tool_access should be present"
    );
}

#[test]
fn merge_deep_merge_matches_expected() {
    let base_yaml = read_fixture("core/merge/base.yaml");
    let child_yaml = read_fixture("core/merge/child-deep-merge.yaml");
    let expected_yaml = read_fixture("core/merge/expected-deep-merge.yaml");
    let base = hushspec::HushSpec::parse(&base_yaml).expect("parse base");
    let child = hushspec::HushSpec::parse(&child_yaml).expect("parse child");
    let expected = hushspec::HushSpec::parse(&expected_yaml).expect("parse expected");
    let merged = hushspec::merge(&base, &child);
    // Both should compile to equivalent policies
    let merged_policy = hushspec_compiler::compile(&merged).expect("compile merged");
    let expected_policy = hushspec_compiler::compile(&expected).expect("compile expected");
    // Compare key fields
    assert_eq!(merged_policy.name, expected_policy.name);
    assert_eq!(
        merged_policy
            .guards
            .egress_allowlist
            .as_ref()
            .map(|e| &e.allow),
        expected_policy
            .guards
            .egress_allowlist
            .as_ref()
            .map(|e| &e.allow),
    );
    assert_eq!(
        merged_policy.guards.forbidden_path.is_some(),
        expected_policy.guards.forbidden_path.is_some(),
    );
}

#[test]
fn merge_replace_matches_expected() {
    let base_yaml = read_fixture("core/merge/base.yaml");
    let child_yaml = read_fixture("core/merge/child-replace.yaml");
    let expected_yaml = read_fixture("core/merge/expected-replace.yaml");
    let base = hushspec::HushSpec::parse(&base_yaml).expect("parse base");
    let child = hushspec::HushSpec::parse(&child_yaml).expect("parse child");
    let expected = hushspec::HushSpec::parse(&expected_yaml).expect("parse expected");
    let merged = hushspec::merge(&base, &child);
    let merged_policy = hushspec_compiler::compile(&merged).expect("compile merged");
    let expected_policy = hushspec_compiler::compile(&expected).expect("compile expected");
    assert_eq!(merged_policy.name, expected_policy.name);
    assert_eq!(
        merged_policy.guards.mcp_tool.is_some(),
        expected_policy.guards.mcp_tool.is_some(),
    );
    assert_eq!(
        merged_policy.guards.egress_allowlist.is_some(),
        expected_policy.guards.egress_allowlist.is_some(),
    );
}

// ===========================================================================
// Built-in HushSpec rulesets should compile to valid policies
// ===========================================================================

#[test]
fn compile_hushspec_default_ruleset() {
    let path = Path::new(HUSHSPEC_SNAPSHOT_DIR).join("rulesets/default.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read default ruleset: {}", e));
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse default ruleset");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "default ruleset should be valid: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile default ruleset");
    assert!(
        policy.guards.forbidden_path.is_some(),
        "default should have forbidden_path"
    );
    assert!(
        policy.guards.egress_allowlist.is_some(),
        "default should have egress"
    );
    assert!(
        policy.guards.secret_leak.is_some(),
        "default should have secret_leak"
    );
    assert!(
        policy.guards.patch_integrity.is_some(),
        "default should have patch_integrity"
    );
    assert!(
        policy.guards.mcp_tool.is_some(),
        "default should have tool_access"
    );
}

#[test]
fn compile_hushspec_strict_ruleset() {
    let path = Path::new(HUSHSPEC_SNAPSHOT_DIR).join("rulesets/strict.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read strict");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse strict");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "strict ruleset should be valid: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile strict");
    assert!(
        policy.guards.forbidden_path.is_some(),
        "strict should have forbidden_path"
    );
    // Strict has empty egress allow list (deny all)
    let egress = policy
        .guards
        .egress_allowlist
        .as_ref()
        .expect("strict egress");
    assert!(
        egress.allow.is_empty(),
        "strict should have no allowed egress domains"
    );
}

#[test]
fn compile_hushspec_permissive_ruleset() {
    let path = Path::new(HUSHSPEC_SNAPSHOT_DIR).join("rulesets/permissive.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read permissive");
    let spec = hushspec::HushSpec::parse(&yaml).expect("parse permissive");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "permissive ruleset should be valid: {:?}",
        validation.errors
    );
    let policy = hushspec_compiler::compile(&spec).expect("compile permissive");
    let egress = policy
        .guards
        .egress_allowlist
        .as_ref()
        .expect("permissive egress");
    assert!(
        egress.allow.contains(&"*".to_string()),
        "permissive should allow wildcard egress"
    );
}
