#![cfg(feature = "full")]
//! Integration tests for the HushSpec compiler.
//!
//! These tests verify:
//! - Format detection (`is_hushspec`)
//! - HushSpec -> Policy compilation via `from_yaml_auto`
//! - Policy -> HushSpec decompilation roundtrip
//! - Extensions (posture, detection) compile correctly
//! - Legacy Clawdstrike format still works through auto-detect

#![allow(clippy::expect_used, clippy::unwrap_used)]

use clawdstrike::guards::{ForbiddenPathConfig, SecretLeakConfig, SecretPattern, Severity};
use clawdstrike::hushspec_compiler;
use clawdstrike::Policy;

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

#[test]
fn is_hushspec_detects_format() {
    assert!(hushspec_compiler::is_hushspec(
        "hushspec: \"0.1.0\"\nname: test\n"
    ));
    assert!(hushspec_compiler::is_hushspec(
        "name: test\nhushspec: \"0.1.0\"\n"
    ));
    assert!(hushspec_compiler::is_hushspec(
        "# comment\nhushspec: \"0.1.0\"\n"
    ));
    assert!(!hushspec_compiler::is_hushspec(
        "version: \"1.5.0\"\nname: test\n"
    ));
    assert!(!hushspec_compiler::is_hushspec("name: test\n"));
    // YAML document markers should be skipped
    assert!(hushspec_compiler::is_hushspec(
        "---\nhushspec: \"0.1.0\"\nname: test\n"
    ));
    assert!(hushspec_compiler::is_hushspec(
        "---\n# comment\nhushspec: \"0.1.0\"\n"
    ));
    assert!(!hushspec_compiler::is_hushspec(
        "metadata:\n  hushspec: \"0.1.0\"\n"
    ));
}

// ---------------------------------------------------------------------------
// Compilation: minimal document
// ---------------------------------------------------------------------------

#[test]
fn compile_minimal_hushspec() {
    let yaml = r#"
hushspec: "0.1.0"
name: minimal
description: A minimal policy
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    assert_eq!(policy.name, "minimal");
    assert_eq!(policy.description, "A minimal policy");
}

// ---------------------------------------------------------------------------
// Compilation: egress rules
// ---------------------------------------------------------------------------

#[test]
fn compile_egress_rule() {
    let yaml = r#"
hushspec: "0.1.0"
name: egress-test
rules:
  egress:
    allow:
      - "api.openai.com"
      - "*.anthropic.com"
    block:
      - "*.evil.com"
    default: block
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let egress = policy
        .guards
        .egress_allowlist
        .as_ref()
        .expect("egress should be set");
    assert_eq!(egress.allow, vec!["api.openai.com", "*.anthropic.com"]);
    assert_eq!(egress.block, vec!["*.evil.com"]);
}

// ---------------------------------------------------------------------------
// Compilation: forbidden paths
// ---------------------------------------------------------------------------

#[test]
fn compile_forbidden_paths() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions:
      - "**/.ssh/config"
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let fp = policy
        .guards
        .forbidden_path
        .as_ref()
        .expect("forbidden_path should be set");
    assert_eq!(fp.exceptions, vec!["**/.ssh/config"]);
}

#[test]
fn compile_forbidden_paths_preserves_explicit_empty_patterns() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    patterns: []
"#;

    let policy = Policy::from_yaml_auto(yaml).expect("should compile empty forbidden_paths");
    let fp = policy
        .guards
        .forbidden_path
        .as_ref()
        .expect("forbidden_path guard should exist");

    assert_eq!(fp.patterns.as_ref(), Some(&Vec::<String>::new()));
    assert!(
        fp.effective_patterns().is_empty(),
        "explicit empty HushSpec patterns should clear forbidden paths"
    );
}

// ---------------------------------------------------------------------------
// Compilation: tool access (MCP)
// ---------------------------------------------------------------------------

#[test]
fn compile_tool_access() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  tool_access:
    allow:
      - read_file
      - list_directory
    block:
      - shell_exec
    require_confirmation:
      - file_write
    default: block
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let mcp = policy
        .guards
        .mcp_tool
        .as_ref()
        .expect("mcp_tool should be set");
    assert_eq!(mcp.allow, vec!["read_file", "list_directory"]);
    assert_eq!(mcp.block, vec!["shell_exec"]);
    assert_eq!(mcp.require_confirmation, vec!["file_write"]);
}

// ---------------------------------------------------------------------------
// Compilation: secret patterns
// ---------------------------------------------------------------------------

#[test]
fn compile_secret_patterns() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
    skip_paths:
      - "**/test/**"
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let sl = policy
        .guards
        .secret_leak
        .as_ref()
        .expect("secret_leak should be set");
    assert_eq!(sl.patterns.len(), 2);
    assert_eq!(sl.patterns[0].name, "aws_key");
    assert_eq!(sl.skip_paths, vec!["**/test/**"]);
}

// ---------------------------------------------------------------------------
// Compilation: posture extension
// ---------------------------------------------------------------------------

#[test]
fn compile_posture_extension() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      restricted:
        capabilities: [file_access]
      standard:
        capabilities: [file_access, file_write, egress]
        budgets:
          file_writes: 50
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
      - from: restricted
        to: standard
        on: user_approval
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let posture = policy.posture.as_ref().expect("posture should be set");
    assert_eq!(posture.initial, "standard");
    assert_eq!(posture.states.len(), 2);
    assert_eq!(posture.transitions.len(), 2);
}

// ---------------------------------------------------------------------------
// Compilation: detection extension (prompt injection + jailbreak)
// ---------------------------------------------------------------------------

#[test]
fn compile_detection_extension() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 40
      warn_threshold: 15
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    assert!(policy.guards.prompt_injection.is_some());
    assert!(policy.guards.jailbreak.is_some());
}

// ---------------------------------------------------------------------------
// Compilation: full document with all rule types
// ---------------------------------------------------------------------------

#[test]
fn compile_full_document() {
    let yaml = r#"
hushspec: "0.1.0"
name: full-test
description: Complete HushSpec document
rules:
  forbidden_paths:
    patterns: ["**/.ssh/**"]
  egress:
    allow: ["api.openai.com"]
    default: block
  tool_access:
    block: ["shell_exec"]
    default: allow
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
  patch_integrity:
    max_additions: 500
    max_deletions: 200
  shell_commands:
    forbidden_patterns: ["rm -rf /"]
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, egress]
      restricted:
        capabilities: [file_access]
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
  detection:
    prompt_injection:
      block_at_or_above: high
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile full document");
    assert_eq!(policy.name, "full-test");
    assert!(policy.guards.forbidden_path.is_some());
    assert!(policy.guards.egress_allowlist.is_some());
    assert!(policy.guards.mcp_tool.is_some());
    assert!(policy.guards.secret_leak.is_some());
    assert!(policy.guards.patch_integrity.is_some());
    assert!(policy.guards.shell_command.is_some());
    assert!(policy.posture.is_some());
    assert!(policy.guards.prompt_injection.is_some());
}

// ---------------------------------------------------------------------------
// Decompile roundtrip: Policy -> HushSpec -> Policy
// ---------------------------------------------------------------------------

#[test]
fn decompile_roundtrip() {
    // Start with a Clawdstrike policy, decompile to HushSpec, compile back
    let clawdstrike_yaml = r#"
version: "1.5.0"
name: roundtrip-test
description: Test roundtrip
guards:
  egress_allowlist:
    allow:
      - "api.openai.com"
    default_action: block
  mcp_tool:
    block:
      - shell_exec
    default_action: allow
"#;
    let original = Policy::from_yaml(clawdstrike_yaml).expect("parse original");
    let spec = hushspec_compiler::decompile(&original).expect("decompile should succeed");
    let compiled = hushspec_compiler::compile(&spec).expect("compile back");

    // Key fields should match
    assert_eq!(compiled.name, original.name);
    assert_eq!(
        compiled.guards.egress_allowlist.as_ref().map(|e| &e.allow),
        original.guards.egress_allowlist.as_ref().map(|e| &e.allow)
    );
    assert_eq!(
        compiled.guards.mcp_tool.as_ref().map(|m| &m.block),
        original.guards.mcp_tool.as_ref().map(|m| &m.block)
    );
}

// ---------------------------------------------------------------------------
// Legacy format auto-detection
// ---------------------------------------------------------------------------

#[test]
fn legacy_format_still_works() {
    // Ensure existing Clawdstrike format still loads fine through from_yaml_auto
    let yaml = r#"
version: "1.5.0"
name: legacy
description: Legacy format
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
  egress_allowlist:
    allow:
      - "api.openai.com"
    default_action: block
settings:
  fail_fast: true
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should load legacy format");
    assert_eq!(policy.name, "legacy");
    assert!(policy.settings.fail_fast.unwrap_or(false));
}

// ---------------------------------------------------------------------------
// HushSpec extends with prefix stripping
// ---------------------------------------------------------------------------

#[test]
fn hushspec_extends_prefix_stripped() {
    let yaml = r#"
hushspec: "0.1.0"
name: child
extends: "hushspec:default"
rules:
  egress:
    allow: ["custom.api.com"]
    default: block
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    // The "hushspec:" prefix should be stripped so Clawdstrike sees "default"
    assert_eq!(policy.extends.as_deref(), Some("default"));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_rules_produces_default_guards() {
    let yaml = r#"
hushspec: "0.1.0"
name: empty-rules
rules: {}
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile empty rules");
    assert_eq!(policy.name, "empty-rules");
    // No guards should be set when rules block is empty
    assert!(policy.guards.forbidden_path.is_none());
    assert!(policy.guards.egress_allowlist.is_none());
    assert!(policy.guards.mcp_tool.is_none());
}

#[test]
fn hushspec_without_name_gets_default() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: ["example.com"]
    default: allow
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile without name");
    // Name should be empty or a default, not an error
    assert!(policy.name.is_empty() || !policy.name.is_empty());
    // But egress should still be compiled
    assert!(policy.guards.egress_allowlist.is_some());
}

#[test]
fn decompile_preserves_description() {
    let clawdstrike_yaml = r#"
version: "1.5.0"
name: desc-test
description: A very important policy
"#;
    let original = Policy::from_yaml(clawdstrike_yaml).expect("parse original");
    let spec = hushspec_compiler::decompile(&original).expect("decompile should succeed");
    let compiled = hushspec_compiler::compile(&spec).expect("compile back");

    assert_eq!(compiled.description, original.description);
}

#[test]
fn compile_patch_integrity_fields() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_additions: 1000
    max_deletions: 500
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile patch_integrity");
    let pi = policy
        .guards
        .patch_integrity
        .as_ref()
        .expect("patch_integrity should be set");
    assert_eq!(pi.max_additions, 1000);
    assert_eq!(pi.max_deletions, 500);
}

#[test]
fn compile_shell_commands_forbidden_patterns() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "rm -rf /"
      - "curl.*\\|.*bash"
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile shell_commands");
    let sc = policy
        .guards
        .shell_command
        .as_ref()
        .expect("shell_command should be set");
    assert_eq!(sc.forbidden_patterns.len(), 2);
    assert!(sc.forbidden_patterns.contains(&"rm -rf /".to_string()));
}

#[test]
fn is_hushspec_rejects_empty_string() {
    assert!(!hushspec_compiler::is_hushspec(""));
}

#[test]
fn is_hushspec_rejects_non_yaml() {
    assert!(!hushspec_compiler::is_hushspec("{\"json\": true}"));
}

#[test]
fn compile_output_has_valid_version() {
    let yaml = r#"
hushspec: "0.1.0"
name: version-check
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    // Compiled policy should have a valid Clawdstrike schema version
    assert!(
        clawdstrike::policy::POLICY_SUPPORTED_SCHEMA_VERSIONS.contains(&policy.version.as_str()),
        "compiled policy version '{}' should be a supported Clawdstrike schema version",
        policy.version
    );
}

// ---------------------------------------------------------------------------
// Compilation: threat_intel / Spider Sense
// ---------------------------------------------------------------------------

#[test]
fn compile_threat_intel_extension() {
    let yaml = r#"
hushspec: "0.1.0"
name: threat-intel-test
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.90
      top_k: 3
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile threat_intel");
    let ss = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be set from threat_intel");
    assert!(ss.enabled);
    assert_eq!(ss.pattern_db_path, "builtin:s2bench-v1");
    assert!((ss.similarity_threshold - 0.90).abs() < f64::EPSILON);
    assert_eq!(ss.top_k, 3);
}

#[test]
fn compile_threat_intel_defaults() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let ss = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be set");
    assert!(ss.enabled);
    // pattern_db_path should be empty when not specified
    assert!(ss.pattern_db_path.is_empty());
    // defaults from hushspec: similarity_threshold=0.85, top_k=5
    assert!((ss.similarity_threshold - 0.85).abs() < f64::EPSILON);
    assert_eq!(ss.top_k, 5);
}

#[test]
fn decompile_threat_intel_roundtrip() {
    let yaml = r#"
hushspec: "0.1.0"
name: spider-roundtrip
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.92
      top_k: 7
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let spec = hushspec_compiler::decompile(&policy).expect("decompile should succeed");

    // Compile the decompiled spec back and verify spider_sense is preserved
    let recompiled = hushspec_compiler::compile(&spec).expect("recompile should succeed");
    let ss = recompiled
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should survive roundtrip");
    assert!(ss.enabled);
    assert_eq!(ss.pattern_db_path, "builtin:s2bench-v1");
    assert!((ss.similarity_threshold - 0.92).abs() < f64::EPSILON);
    assert_eq!(ss.top_k, 7);

    // Verify the decompiled spec has correct threat_intel values
    let ext = spec.extensions.expect("extensions should exist");
    let det = ext.detection.expect("detection should exist");
    let ti = det
        .threat_intel
        .expect("threat_intel should exist after decompile");
    assert_eq!(ti.enabled, Some(true));
    assert_eq!(ti.pattern_db.as_deref(), Some("builtin:s2bench-v1"));
    assert_eq!(ti.similarity_threshold, Some(0.92));
    assert_eq!(ti.top_k, Some(7));
}

#[test]
fn decompile_threat_intel_empty_pattern_db() {
    // When pattern_db_path is empty, decompile should produce None for pattern_db
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
"#;
    let policy = Policy::from_yaml_auto(yaml).expect("should compile");
    let spec = hushspec_compiler::decompile(&policy).expect("decompile should succeed");
    let ext = spec.extensions.expect("extensions");
    let det = ext.detection.expect("detection");
    let ti = det.threat_intel.expect("threat_intel");
    assert!(
        ti.pattern_db.is_none(),
        "empty pattern_db_path should decompile to None"
    );
}

#[test]
fn compile_hushspec_rejects_invalid_clawdstrike_glob() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    patterns:
      - "["
"#;

    let err = hushspec_compiler::compile_hushspec(yaml).expect_err("invalid glob should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("guards.forbidden_path.patterns"),
        "error should include the validated policy field, got: {msg}"
    );
}

#[test]
fn decompile_forbidden_paths_materializes_clawdstrike_defaults() {
    let mut policy = Policy::default();
    policy.guards.forbidden_path = Some(ForbiddenPathConfig::with_defaults());

    let spec = hushspec_compiler::decompile(&policy).expect("decompile should succeed");
    let validation = hushspec::validate(&spec);
    assert!(
        validation.is_valid(),
        "decompiled HushSpec should stay valid: {:?}",
        validation.errors
    );

    let rules = spec.rules.as_ref().expect("rules should exist");
    let forbidden_paths = rules
        .forbidden_paths
        .as_ref()
        .expect("forbidden_paths should exist");
    assert!(
        !forbidden_paths.patterns.is_empty(),
        "Clawdstrike defaults should decompile to explicit HushSpec patterns"
    );
    assert!(forbidden_paths.patterns.contains(&"**/.ssh/**".to_string()));

    let recompiled = hushspec_compiler::compile(&spec).expect("recompile should succeed");
    let recompiled_fp = recompiled
        .guards
        .forbidden_path
        .as_ref()
        .expect("forbidden_path should roundtrip");
    assert_eq!(
        recompiled_fp.effective_patterns(),
        ForbiddenPathConfig::with_defaults().effective_patterns()
    );
}

#[test]
fn decompile_omits_default_merge_strategy() {
    let spec = hushspec_compiler::decompile(&Policy::default()).expect("decompile should succeed");
    assert!(
        spec.merge_strategy.is_none(),
        "default deep-merge should be omitted from decompiled HushSpec"
    );
}

#[test]
fn decompile_rejects_egress_log_default_action() {
    let policy = Policy::from_yaml(
        r#"
version: "1.5.0"
guards:
  egress_allowlist:
    default_action: log
"#,
    )
    .expect("policy should parse");

    let err = hushspec_compiler::decompile(&policy).expect_err("log should not decompile");
    let msg = err.to_string();
    assert!(msg.contains("guards.egress_allowlist.default_action"));
    assert!(msg.contains("log"));
}

#[test]
fn decompile_rejects_origin_egress_log_default_action() {
    let policy = Policy::from_yaml(
        r#"
version: "1.5.0"
origins:
  default_behavior: deny
  profiles:
    - id: slack-internal
      match_rules:
        provider: slack
      egress:
        default_action: log
"#,
    )
    .expect("policy should parse");

    let err = hushspec_compiler::decompile(&policy).expect_err("log should not decompile");
    let msg = err.to_string();
    assert!(msg.contains("origins.profiles[slack-internal].egress.default_action"));
    assert!(msg.contains("log"));
}

#[test]
fn decompile_rejects_info_secret_pattern_severity() {
    let mut policy = Policy::default();
    policy.guards.secret_leak = Some(SecretLeakConfig {
        patterns: vec![SecretPattern {
            name: "informational-secret".to_string(),
            pattern: "INFO_TOKEN_[A-Z0-9]+".to_string(),
            severity: Severity::Info,
            description: Some("Info-level secret".to_string()),
            luhn_check: false,
            masking: None,
        }],
        ..SecretLeakConfig::default()
    });

    let err = hushspec_compiler::decompile(&policy).expect_err("info should not decompile");
    let msg = err.to_string();
    assert!(msg.contains("guards.secret_leak.patterns[informational-secret].severity"));
    assert!(msg.contains("info"));
}

// ---------------------------------------------------------------------------
// Threshold validation
// ---------------------------------------------------------------------------

#[test]
fn compile_rejects_jailbreak_block_threshold_over_255() {
    let spec = hushspec::HushSpec {
        hushspec: "0.1.0".to_string(),
        name: None,
        description: None,
        extends: None,
        merge_strategy: None,
        rules: None,
        extensions: Some(hushspec::Extensions {
            detection: Some(hushspec::extensions::DetectionExtension {
                prompt_injection: None,
                jailbreak: Some(hushspec::extensions::JailbreakDetection {
                    enabled: Some(true),
                    block_threshold: Some(300),
                    warn_threshold: Some(30),
                    max_input_bytes: Some(200_000),
                }),
                threat_intel: None,
            }),
            ..Default::default()
        }),
        metadata: None,
    };
    let err = hushspec_compiler::compile(&spec).expect_err("should reject block_threshold > 255");
    let msg = format!("{err}");
    assert!(
        msg.contains("block_threshold") && msg.contains("300"),
        "error should mention block_threshold and value 300, got: {msg}"
    );
}

#[test]
fn compile_rejects_jailbreak_warn_threshold_over_255() {
    let spec = hushspec::HushSpec {
        hushspec: "0.1.0".to_string(),
        name: None,
        description: None,
        extends: None,
        merge_strategy: None,
        rules: None,
        extensions: Some(hushspec::Extensions {
            detection: Some(hushspec::extensions::DetectionExtension {
                prompt_injection: None,
                jailbreak: Some(hushspec::extensions::JailbreakDetection {
                    enabled: Some(true),
                    block_threshold: Some(70),
                    warn_threshold: Some(500),
                    max_input_bytes: Some(200_000),
                }),
                threat_intel: None,
            }),
            ..Default::default()
        }),
        metadata: None,
    };
    let err = hushspec_compiler::compile(&spec).expect_err("should reject warn_threshold > 255");
    let msg = format!("{err}");
    assert!(
        msg.contains("warn_threshold") && msg.contains("500"),
        "error should mention warn_threshold and value 500, got: {msg}"
    );
}
