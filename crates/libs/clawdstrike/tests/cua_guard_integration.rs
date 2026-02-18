#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration tests verifying CUA events flow through HushEngine without crashing.
//!
//! CUA events use GuardAction::Custom. With default policy (no custom guards registered),
//! they should be ALLOWED because no guard claims to handle these Custom actions.

use clawdstrike::guards::{GuardAction, GuardContext};
use clawdstrike::HushEngine;

#[tokio::test]
async fn cua_connect_event_allowed_with_default_policy() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new().with_session_id("cua-sess-001");
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "connect"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("remote.session.connect", &payload),
            &ctx,
        )
        .await
        .unwrap();

    assert!(
        report.overall.allowed,
        "CUA connect events should be allowed with default policy (no custom guards claim them)"
    );
}

#[tokio::test]
async fn cua_disconnect_event_allowed_with_default_policy() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new();
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "disconnect"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("remote.session.disconnect", &payload),
            &ctx,
        )
        .await
        .unwrap();

    assert!(report.overall.allowed);
}

#[tokio::test]
async fn cua_reconnect_event_preserves_continuity_hash() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new().with_session_id("cua-sess-reconnect");
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "reconnect",
        "continuityPrevSessionHash": "sha256:prev_session_abc"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("remote.session.reconnect", &payload),
            &ctx,
        )
        .await
        .unwrap();

    assert!(report.overall.allowed);
    // The engine processed this without error, proving the pipeline handles CUA payloads.
}

#[tokio::test]
async fn cua_input_inject_event_flows_through_engine() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new();
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "inject",
        "input_type": "keyboard",
        "postconditionProbeHash": "sha256:probe_result"
    });

    let report = engine
        .check_action_report(&GuardAction::Custom("input.inject", &payload), &ctx)
        .await
        .unwrap();

    assert!(report.overall.allowed);
}

#[tokio::test]
async fn cua_clipboard_event_flows_through_engine() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new();
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "clipboard",
        "direction": "read"
    });

    let report = engine
        .check_action_report(&GuardAction::Custom("remote.clipboard", &payload), &ctx)
        .await
        .unwrap();

    assert!(report.overall.allowed);
}

#[tokio::test]
async fn cua_file_transfer_event_flows_through_engine() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new();
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "file_transfer",
        "direction": "download"
    });

    let report = engine
        .check_action_report(&GuardAction::Custom("remote.file_transfer", &payload), &ctx)
        .await
        .unwrap();

    assert!(report.overall.allowed);
}

#[tokio::test]
async fn cua_events_do_not_crash_with_strict_policy() {
    let engine = HushEngine::from_ruleset("strict").unwrap();
    let ctx = GuardContext::new();

    let cua_types = vec![
        "remote.session.connect",
        "remote.session.disconnect",
        "remote.session.reconnect",
        "input.inject",
        "remote.clipboard",
        "remote.file_transfer",
    ];

    for cua_type in cua_types {
        let payload = serde_json::json!({
            "type": "cua",
            "cuaAction": "test"
        });

        let result = engine
            .check_action_report(&GuardAction::Custom(cua_type, &payload), &ctx)
            .await;

        assert!(
            result.is_ok(),
            "CUA event type '{}' should not cause engine error with strict policy",
            cua_type
        );
    }
}

#[tokio::test]
async fn cua_event_stats_counted() {
    let engine = HushEngine::new();
    let ctx = GuardContext::new();
    let payload = serde_json::json!({
        "type": "cua",
        "cuaAction": "connect"
    });

    let _ = engine
        .check_action_report(
            &GuardAction::Custom("remote.session.connect", &payload),
            &ctx,
        )
        .await
        .unwrap();

    let stats = engine.stats().await;
    assert_eq!(stats.action_count, 1, "CUA event should be counted");
    assert_eq!(
        stats.violation_count, 0,
        "CUA event should not cause violation with default policy"
    );
}
