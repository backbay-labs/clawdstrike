//! Integration test that verifies the `#[clawdstrike_guard]` proc macro
//! generates valid ABI exports that compile and behave correctly on native
//! targets.

#![allow(clippy::unwrap_used)]

use clawdstrike_guard_sdk::prelude::*;

/// A trivial guard that denies everything for testing.
#[clawdstrike_guard]
#[derive(Default)]
struct DenyAllGuard;

impl Guard for DenyAllGuard {
    fn name(&self) -> &str {
        "test.deny-all"
    }

    fn handles(&self, _action_type: &str) -> bool {
        true
    }

    fn check(&self, _input: GuardInput) -> GuardOutput {
        GuardOutput::deny(Severity::Error, "Denied by test guard")
    }
}

#[test]
fn init_returns_abi_version_1() {
    let version = clawdstrike_guard_init();
    assert_eq!(version, 1);
}

#[test]
fn guard_trait_handles_returns_true() {
    // Test the Guard trait implementation directly (safe on native targets).
    // The raw ABI functions (clawdstrike_guard_handles/check) use raw pointer
    // casts that only work correctly inside the WASM linear memory sandbox.
    let guard = DenyAllGuard;
    assert!(Guard::handles(&guard, "tool_call"));
    assert!(Guard::handles(&guard, "file_access"));
}

#[test]
fn guard_trait_check_denies() {
    let guard = DenyAllGuard;
    let input = GuardInput {
        guard: "test.deny-all".to_string(),
        action_type: Some("tool_call".to_string()),
        payload: json!({}),
        config: json!({}),
    };
    let output = Guard::check(&guard, input);
    assert!(!output.allowed);
    assert_eq!(output.message.as_deref(), Some("Denied by test guard"));
}

#[test]
fn guard_output_allow_serialization() {
    let output = GuardOutput::allow();
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["allowed"], true);
    assert_eq!(json["severity"], "info");
    assert_eq!(json["message"], "Allowed");
}

#[test]
fn guard_output_deny_serialization() {
    let output = GuardOutput::deny(Severity::Error, "blocked");
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["allowed"], false);
    assert_eq!(json["severity"], "error");
    assert_eq!(json["message"], "blocked");
}

#[test]
fn guard_output_deny_with_details_serialization() {
    let output = GuardOutput::deny_with_details(
        Severity::Critical,
        "critical block",
        json!({"reason": "test"}),
    );
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["allowed"], false);
    assert_eq!(json["severity"], "critical");
    assert_eq!(json["details"]["reason"], "test");
}

#[test]
fn verdict_allow_conversion() {
    let verdict = Verdict::Allow {
        message: Some("all good".to_string()),
    };
    let output: GuardOutput = verdict.into();
    assert!(output.allowed);
    assert_eq!(output.message.as_deref(), Some("all good"));
}

#[test]
fn verdict_deny_conversion() {
    let verdict = Verdict::Deny {
        severity: Severity::Warning,
        message: "not so fast".to_string(),
        details: None,
    };
    let output: GuardOutput = verdict.into();
    assert!(!output.allowed);
    assert_eq!(output.severity.as_deref(), Some("warning"));
    assert_eq!(output.message.as_deref(), Some("not so fast"));
}

#[test]
fn guard_input_deserialization() {
    let json = r#"{
        "guard": "test.guard",
        "action_type": "file_access",
        "payload": {"path": "/etc/passwd"},
        "config": {"strict": true}
    }"#;
    let input: GuardInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.guard, "test.guard");
    assert_eq!(input.action_type.as_deref(), Some("file_access"));
    assert_eq!(input.payload["path"], "/etc/passwd");
    assert_eq!(input.config["strict"], true);
}

#[test]
fn guard_input_deserialization_minimal() {
    let json = r#"{"guard": "test.guard", "payload": {}}"#;
    let input: GuardInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.guard, "test.guard");
    assert!(input.action_type.is_none());
}

#[test]
fn capability_repr_values() {
    assert_eq!(Capability::Network as i32, 0);
    assert_eq!(Capability::Subprocess as i32, 1);
    assert_eq!(Capability::FsRead as i32, 2);
    assert_eq!(Capability::FsWrite as i32, 3);
    assert_eq!(Capability::Secrets as i32, 4);
}

#[test]
fn severity_as_str() {
    assert_eq!(Severity::Info.as_str(), "info");
    assert_eq!(Severity::Warning.as_str(), "warning");
    assert_eq!(Severity::Error.as_str(), "error");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn guard_output_with_guard_name() {
    let output = GuardOutput::allow().with_guard("custom.name");
    assert_eq!(output.guard.as_deref(), Some("custom.name"));
}

#[test]
fn guard_output_with_details() {
    let output = GuardOutput::allow().with_details(json!({"key": "value"}));
    assert_eq!(output.details.as_ref().unwrap()["key"], "value");
}
