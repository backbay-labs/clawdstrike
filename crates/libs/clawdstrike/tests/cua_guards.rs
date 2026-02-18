#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Tests for the three CUA guards: computer_use, remote_desktop_side_channel,
//! and input_injection_capability.

use clawdstrike::guards::{
    ComputerUseConfig, ComputerUseGuard, ComputerUseMode, Guard, GuardAction, GuardContext,
    InputInjectionCapabilityConfig, InputInjectionCapabilityGuard, RemoteDesktopSideChannelConfig,
    RemoteDesktopSideChannelGuard,
};

// ── computer_use guard ──

#[tokio::test]
async fn computer_use_allows_known_action_in_guardrail_mode() {
    let guard = ComputerUseGuard::new(); // default is guardrail mode
    let ctx = GuardContext::new();
    let data = serde_json::json!({"type": "cua"});

    let result = guard
        .check(&GuardAction::Custom("remote.session.connect", &data), &ctx)
        .await;
    assert!(
        result.allowed,
        "known CUA action should be allowed in guardrail mode"
    );
}

#[tokio::test]
async fn computer_use_denies_unknown_action_in_fail_closed_mode() {
    let config = ComputerUseConfig {
        mode: ComputerUseMode::FailClosed,
        allowed_actions: vec!["remote.session.connect".to_string()],
        ..Default::default()
    };
    let guard = ComputerUseGuard::with_config(config);
    let ctx = GuardContext::new();
    let data = serde_json::json!({});

    let result = guard
        .check(&GuardAction::Custom("remote.unknown_thing", &data), &ctx)
        .await;
    assert!(
        !result.allowed,
        "unknown action must be denied in fail_closed mode"
    );
}

#[tokio::test]
async fn computer_use_allows_everything_in_observe_mode() {
    let config = ComputerUseConfig {
        mode: ComputerUseMode::Observe,
        allowed_actions: vec![], // empty allowlist
        ..Default::default()
    };
    let guard = ComputerUseGuard::with_config(config);
    let ctx = GuardContext::new();
    let data = serde_json::json!({});

    let result = guard
        .check(&GuardAction::Custom("remote.whatever", &data), &ctx)
        .await;
    assert!(
        result.allowed,
        "observe mode must always allow, even with empty allowlist"
    );
}

// ── remote_desktop_side_channel guard ──

#[tokio::test]
async fn side_channel_denies_when_clipboard_disabled() {
    let config = RemoteDesktopSideChannelConfig {
        clipboard_enabled: false,
        ..Default::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let ctx = GuardContext::new();
    let data = serde_json::json!({"direction": "read"});

    let result = guard
        .check(&GuardAction::Custom("remote.clipboard", &data), &ctx)
        .await;
    assert!(
        !result.allowed,
        "clipboard should be denied when clipboard_enabled is false"
    );
}

#[tokio::test]
async fn side_channel_allows_when_clipboard_enabled() {
    let config = RemoteDesktopSideChannelConfig {
        clipboard_enabled: true,
        ..Default::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let ctx = GuardContext::new();
    let data = serde_json::json!({"direction": "read"});

    let result = guard
        .check(&GuardAction::Custom("remote.clipboard", &data), &ctx)
        .await;
    assert!(
        result.allowed,
        "clipboard should be allowed when clipboard_enabled is true"
    );
}

// ── input_injection_capability guard ──

#[tokio::test]
async fn input_injection_denies_unknown_input_type() {
    let guard = InputInjectionCapabilityGuard::new();
    let ctx = GuardContext::new();
    let data = serde_json::json!({"input_type": "gamepad"});

    let result = guard
        .check(&GuardAction::Custom("input.inject", &data), &ctx)
        .await;
    assert!(
        !result.allowed,
        "unknown input type 'gamepad' should be denied"
    );
}

#[tokio::test]
async fn input_injection_requires_postcondition_probe_when_configured() {
    let config = InputInjectionCapabilityConfig {
        require_postcondition_probe: true,
        ..Default::default()
    };
    let guard = InputInjectionCapabilityGuard::with_config(config);
    let ctx = GuardContext::new();

    // Without postcondition_probe_hash
    let data = serde_json::json!({"input_type": "keyboard"});
    let result = guard
        .check(&GuardAction::Custom("input.inject", &data), &ctx)
        .await;
    assert!(
        !result.allowed,
        "should deny when postcondition probe is required but missing"
    );

    // With postcondition_probe_hash
    let data = serde_json::json!({
        "input_type": "keyboard",
        "postcondition_probe_hash": "sha256:abc123"
    });
    let result = guard
        .check(&GuardAction::Custom("input.inject", &data), &ctx)
        .await;
    assert!(
        result.allowed,
        "should allow when postcondition probe is present"
    );
}

// ── handles() returns false for non-CUA actions ──

#[test]
fn all_three_guards_skip_non_cua_actions() {
    let computer_use = ComputerUseGuard::new();
    let side_channel = RemoteDesktopSideChannelGuard::new();
    let input_injection = InputInjectionCapabilityGuard::new();

    // FileAccess is not a CUA action
    let file_action = GuardAction::FileAccess("/tmp/test.txt");
    assert!(
        !computer_use.handles(&file_action),
        "computer_use should not handle FileAccess"
    );
    assert!(
        !side_channel.handles(&file_action),
        "side_channel should not handle FileAccess"
    );
    assert!(
        !input_injection.handles(&file_action),
        "input_injection should not handle FileAccess"
    );

    // NetworkEgress is not a CUA action
    let net_action = GuardAction::NetworkEgress("example.com", 443);
    assert!(!computer_use.handles(&net_action));
    assert!(!side_channel.handles(&net_action));
    assert!(!input_injection.handles(&net_action));

    // Custom with non-CUA prefix
    let data = serde_json::json!({});
    let other_custom = GuardAction::Custom("some.other.action", &data);
    assert!(!computer_use.handles(&other_custom));
    assert!(!side_channel.handles(&other_custom));
    assert!(!input_injection.handles(&other_custom));
}
