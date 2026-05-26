use super::signing::{parse_signed_posture_command_payload, transition_posture_command};
use super::types::VALID_POSTURES;
use super::*;
use crate::session::SessionManager;
use crate::settings::Settings;
use axum::{extract::Path, http::StatusCode, routing::post, Json, Router};
use hush_core::Keypair;
use spine::envelope::{build_signed_envelope, now_rfc3339};
use std::sync::Mutex as StdMutex;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[test]
fn command_subject_format() {
    assert_eq!(
        PostureCommandHandler::command_subject("tenant-acme.clawdstrike", "agent-xyz"),
        "tenant-acme.clawdstrike.posture.command.agent-xyz"
    );
}

#[test]
fn set_posture_command_deserializes() {
    let json = r#"{"command":"set_posture","posture":"restricted"}"#;
    let cmd: PostureCommand = serde_json::from_str(json).unwrap();
    match cmd {
        PostureCommand::SetPosture { posture } => {
            assert_eq!(posture, "restricted");
        }
        other => panic!("expected SetPosture, got {:?}", other),
    }
}

#[test]
fn kill_switch_command_deserializes() {
    let json = r#"{"command":"kill_switch","reason":"security breach"}"#;
    let cmd: PostureCommand = serde_json::from_str(json).unwrap();
    match cmd {
        PostureCommand::KillSwitch { reason } => {
            assert_eq!(reason.as_deref(), Some("security breach"));
        }
        other => panic!("expected KillSwitch, got {:?}", other),
    }
}

#[test]
fn kill_switch_without_reason_deserializes() {
    let json = r#"{"command":"kill_switch"}"#;
    let cmd: PostureCommand = serde_json::from_str(json).unwrap();
    match cmd {
        PostureCommand::KillSwitch { reason } => {
            assert!(reason.is_none());
        }
        other => panic!("expected KillSwitch, got {:?}", other),
    }
}

#[test]
fn request_policy_reload_deserializes() {
    let json = r#"{"command":"request_policy_reload"}"#;
    let cmd: PostureCommand = serde_json::from_str(json).unwrap();
    assert!(matches!(cmd, PostureCommand::RequestPolicyReload));
}

#[test]
fn signed_posture_command_requires_trusted_issuer() {
    let kp = Keypair::generate();
    let envelope = build_signed_envelope(
        &kp,
        1,
        None,
        serde_json::json!({
            "command": "request_policy_reload"
        }),
        now_rfc3339(),
    )
    .unwrap();
    let err = parse_signed_posture_command_payload(&serde_json::to_vec(&envelope).unwrap(), None)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("missing trusted posture command issuer"));
}

#[test]
fn signed_posture_command_accepts_matching_issuer() {
    let kp = Keypair::generate();
    let envelope = build_signed_envelope(
        &kp,
        1,
        None,
        serde_json::json!({
            "command": "request_policy_reload"
        }),
        now_rfc3339(),
    )
    .unwrap();
    let issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let parsed = parse_signed_posture_command_payload(
        &serde_json::to_vec(&envelope).unwrap(),
        Some(&issuer),
    )
    .unwrap();
    assert!(matches!(parsed, PostureCommand::RequestPolicyReload));
}

#[test]
fn valid_postures_are_accepted() {
    for posture in VALID_POSTURES {
        assert!(
            VALID_POSTURES.contains(posture),
            "posture '{}' should be valid",
            posture
        );
    }
}

#[test]
fn unknown_posture_is_rejected() {
    assert!(!VALID_POSTURES.contains(&"bogus"));
    assert!(!VALID_POSTURES.contains(&""));
    assert!(!VALID_POSTURES.contains(&"STANDARD")); // case-sensitive
}

async fn start_transition_test_server(events: std::sync::Arc<StdMutex<Vec<String>>>) -> String {
    let events_for_create = events.clone();
    let events_for_transition = events.clone();
    let app = Router::new()
        .route(
            "/api/v1/session",
            post(move || {
                let events_for_create = events_for_create.clone();
                async move {
                    events_for_create
                        .lock()
                        .unwrap()
                        .push("create:sess-1".to_string());
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "session": { "session_id": "sess-1" }
                        })),
                    )
                }
            }),
        )
        .route(
            "/api/v1/session/{id}/transition",
            post(
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let events_for_transition = events_for_transition.clone();
                    async move {
                        let to_state = body
                            .get("to_state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let trigger = body
                            .get("trigger")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        events_for_transition
                            .lock()
                            .unwrap()
                            .push(format!("transition:{id}:{to_state}:{trigger}"));
                        StatusCode::OK
                    }
                },
            ),
        );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|err| panic!("failed to bind transition test server: {err}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("failed to read transition test server address: {err}"));
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|err| panic!("transition test server failed: {err}"));
    });
    format!("http://{}", addr)
}

#[tokio::test]
async fn set_posture_transition_uses_hushd_api_path() {
    let events = std::sync::Arc::new(StdMutex::new(Vec::new()));
    let daemon_url = start_transition_test_server(events.clone()).await;

    let session_manager = SessionManager::new();
    session_manager
        .create_session(&daemon_url, None)
        .await
        .unwrap_or_else(|err| panic!("create_session failed: {err}"));

    let daemon_port = daemon_url
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("failed to parse daemon test port from {daemon_url}"));
    let settings = RwLock::new(Settings {
        daemon_port,
        ..Settings::default()
    });

    let response = transition_posture_command(
        &session_manager,
        &settings,
        "restricted",
        "remote_command",
        "Posture set to restricted".to_string(),
        "No active session".to_string(),
        "transition failed".to_string(),
    )
    .await;
    assert_eq!(response.status, "ok");

    let got = events.lock().unwrap().clone();
    assert!(got.contains(&"create:sess-1".to_string()));
    assert!(got.contains(&"transition:sess-1:restricted:remote_command".to_string()));
}

#[tokio::test]
async fn kill_switch_transition_uses_hushd_api_path() {
    let events = std::sync::Arc::new(StdMutex::new(Vec::new()));
    let daemon_url = start_transition_test_server(events.clone()).await;

    let session_manager = SessionManager::new();
    session_manager
        .create_session(&daemon_url, None)
        .await
        .unwrap_or_else(|err| panic!("create_session failed: {err}"));

    let daemon_port = daemon_url
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("failed to parse daemon test port from {daemon_url}"));
    let settings = RwLock::new(Settings {
        daemon_port,
        ..Settings::default()
    });

    let response = transition_posture_command(
        &session_manager,
        &settings,
        "locked",
        "user_denial",
        "Kill switch activated".to_string(),
        "No active session".to_string(),
        "kill switch failed".to_string(),
    )
    .await;
    assert_eq!(response.status, "ok");

    let got = events.lock().unwrap().clone();
    assert!(got.contains(&"transition:sess-1:locked:user_denial".to_string()));
}
